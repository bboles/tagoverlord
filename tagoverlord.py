from argparse import ArgumentParser
import boto3
import boto3.session
import os, sys, logging, time, threading, traceback, datetime, arrow
from slackit import *

logger = logging.getLogger('root')
FORMAT = '[%(levelname)s:%(asctime)s:%(lineno)4s - %(funcName)20s()]  %(message)s'
logging.basicConfig(format=FORMAT)

debugMode = False


if 'AWS_ACCESS_KEY_ID' not in os.environ:
    print("Please set your AWS_ACCESS_KEY_ID in your environment.")
    sys.exit(1)

if 'AWS_SECRET_ACCESS_KEY' not in os.environ:
    print ("Please set your AWS_SECRET_ACCESS_KEY in your environment.")
    sys.exit(1)

aws_access_key_id = os.environ['AWS_ACCESS_KEY_ID']
aws_secret_access_key = os.environ['AWS_SECRET_ACCESS_KEY']

aws_regions = []
supported_types = ['ec2', 'vol']
desired_tags = ['Name', 'Owner', 'Env', 'Service', 'Product', 'Portfolio']
lower_case_tags = []
for lower_case_tag in desired_tags:
    lower_case_tags.append(lower_case_tag.lower())


ec2_state_filter = {
    'Name': 'instance-state-name',
    'Values': ['running', 'stopped', 'stopping', 'rebooting', 'pending']
}


#current_time         = str(datetime.utcnow().replace(microsecond=0).isoformat())
#current_time         = datetime.datetime.utcnow()
#time_for_next_action = current_time + datetime.timedelta(days=1)    # one day from now
log_types = ['INFO', 'DEBUG']
current_time = arrow.utcnow().format('YYYY-MM-DDTHH:mm:ss')
yes_or_no = 'no'
next_action = 'notify'
current_action = 'none'
slack_channel = '#aws-tag-monitor'
actiondayinterval = 1


def find_ec2_regions():
    ec2 = boto3.client('ec2')
    regions = ec2.describe_regions()
    for region in regions['Regions']:
        aws_regions.append(region['RegionName'])
    return aws_regions


def find_ec2_instances(region, instance_id):
    logger.info("Report for EC2: {0}".format(region))
    session = boto3.session.Session()
    ec2_client = session.resource('ec2', region)

    if instance_id is None:
        instances = ec2_client.instances.all().filter(Filters=[ec2_state_filter])
        return instances
    else:
        try:
            instances = ec2_client.instances.filter(Filters=[ec2_state_filter], InstanceIds=[instance_id])
        except:
            pass

        if not len(list(instances)):
            logger.info("Nothing found in {0}".format(region))
        else:
            for instance in instances:
                logger.info("instances: {0}".format(instances))
            return instances


def missing_tag(instance):
    logger.info("Starting missing_tag")
    instance_tag = []
    try:
        for tag in instance.tags:
            instance_tag.append(tag['Key'])
            missing_tags_set = set(desired_tags) - set(instance_tag)

        if len(missing_tags_set) == 0:
            return None
        else:
            instance_name_tag = get_instance_tag(instance, 'Name')
            if not instance_name_tag:
                instance_name_tag = instance.id
            logger.info("{0} - {1} - Name: {2} - Missing Tags: {3}".format(instance.id, instance.instance_type,
                                                                               instance_name_tag, list(missing_tags_set)))
            return list(missing_tags_set)
    except:
        logger.info("Instance {0} has no tags.".format(instance.id))
        is_orphan_tag(instance, "yes")
        next_action_tag(instance, 'shutdown')   # we want orphaned instances to be shutdown immediately
        return desired_tags


def tag_overlord(instance, region, missing_tags):
    logger.info("Starting tag_overlord.")

    # check to see if we are currently in violation
    is_in_violation_now = get_instance_tag(instance, 'ha_tagoverlord_is_in_violation')
    instance_owner = get_instance_tag(instance, 'Owner')
    instance_name = get_instance_tag(instance, 'Name')

    # if we have a Name tag then we're not an orphan but we can still be in violation
    if instance_name:
        is_orphan_tag(instance, 'no')

    if is_in_violation_now == 'no':
        # put us in violation since we aren't at this point
        violation_timestamp_tag(instance, current_time)
        is_in_violation_now_tag(instance, 'yes')
        time_for_next_action = arrow.get(violation_timestamp).replace(days=actiondayinterval)

        # if we don't know who owns the instance can't do this.
        if instance_owner:
            violation_timestamp = get_instance_tag(instance, 'ha_tagoverlord_violation_timestamp')
            notify_owner(instance, region, 'notify', instance_owner, instance_name, missing_tags, time_for_next_action)
    else:   # not our first time in violation since we're here
        violation_timestamp = get_instance_tag(instance, 'ha_tagoverlord_violation_timestamp')
        time_for_next_action = arrow.get(violation_timestamp).replace(days=1)                  # one day from violation

        # this is so we can have a flag for testing
        if nowait:
            gotime = True
        elif arrow.get(current_time) > time_for_next_action:
            gotime = True
        else:
            gotime = False

        if gotime:

            current_action = get_instance_tag(instance, 'ha_tagoverlord_next_action')

            if current_action == 'notify':
                if instance_owner:
                    notify_owner(instance, region, 'notify', instance_owner, instance_name, missing_tags, time_for_next_action)
                else:
                    is_orphan_tag(instance, 'yes')

                notify_channel(instance, region, 'notify', instance_name, missing_tags)
                next_action_tag(instance, 'shutdown')
            elif current_action == 'shutdown':
                if instance_owner:
                    notify_owner(instance, region, 'shutdown', instance_owner, instance_name, missing_tags, time_for_next_action)
                else:
                    is_orphan_tag(instance, 'yes')

                notify_channel(instance, region, 'shutdown', instance_name, missing_tags)
                shutdown_instance(instance, region)
                next_action_tag(instance, 'terminate')
            elif current_action == 'terminate':
                if instance_owner:
                    notify_owner(instance, region, 'terminate', instance_owner, instance_name, missing_tags, time_for_next_action)
                else:
                    is_orphan_tag(instance, 'yes')

                notify_channel(instance, region, 'terminate', instance_name, missing_tags)
                terminate_instance(instance, region)
                next_action_tag(instance, 'notify')
        else:
            logger.info("Instance {0} is in violation but it isn't time to do anything yet.".format(instance.id))


def get_instance_tag(ec2_item, tag_key):
    logger.info("Starting get_instance_tag.")
    try:
        for tag in ec2_item.tags:
            if tag['Key'] == tag_key:
                logger.debug("get_instance_tag: returning value {0} for key {1}".format(tag['Value'], tag['Key']))
                return tag['Value']
    except:
        logger.debug("tag: {0} not found".format(tag_key))
        return False


def first_run_tags(instance):
    logger.info("Adding the appropriate tags since this is the first time we are running on this instance.")

    is_in_violation_now_tag(instance, 'no')
    next_action_tag(instance, next_action)


def current_run_timestamp_tag(instance, current_time):
    logger.info("Add/modify a ha_tagoverlord_current_run current UTC timestamp.")

    #set_tag(instance, "ha_tagoverlord_current_run", str(current_time.replace(microsecond=0).isoformat()))
    set_tag(instance, "ha_tagoverlord_current_run", str(current_time))


def violation_timestamp_tag(instance, current_time):
    logger.info("Add/modify ha_tagoverlord_violation_timestamp tag.")

    #set_tag(instance, "ha_tagoverlord_violation_timestamp", str(current_time.replace(microsecond=0).isoformat()))
    set_tag(instance, "ha_tagoverlord_violation_timestamp", str(current_time))


def is_in_violation_now_tag(instance, yes_or_no):
    logger.info("Add/modify a ha_tagoverlord_is_in_violation tag.")

    set_tag(instance, "ha_tagoverlord_is_in_violation", yes_or_no)


def next_action_tag(instance, next_action):
    logger.info("Add/modify a ha_tagoverlord_next_action tag.")

    set_tag(instance, "ha_tagoverlord_next_action", next_action)


def is_orphan_tag(instance, yes_or_no):
    logger.info("Add/modify a ha_tagoverlord_orphan tag.")

    set_tag(instance, "ha_tagoverlord_orphan", yes_or_no)


def set_tag(ec2_item, tag_key, tag_value):
    logger.info("ADDING TAG: {0} to {1}".format(tag_key, ec2_item.id))
    try:
        ec2_item.create_tags(DryRun=debugMode, Tags=[{"Key": tag_key, "Value": tag_value}])
        return True
    except:
        print(traceback.print_exc(file=sys.stdout))
        logger.info("Failed to add tag {0} : {1} on {2}".format(tag_key, tag_value, ec2_item.id))


def notify_owner(instance, region, notification_type, instance_owner, instance_name, missing_tags, time_for_next_action):
    logger.info("Notifying owner.")

    if dryrun:
        logger.debug("--dryrun flag was set so not doing anything")
        return

    # turn this back into an object so we can get epoch from it
    time_for_next_action = arrow.get(time_for_next_action)

    # this is more readable as a str
    missing_tags = ', '.join(missing_tags)

    # use the instance name and id if we have a Name tag
    if instance_name:
        name_msg = instance_name + ', ' + instance.id
    else:
        name_msg = instance.id

    # the formatting below is specific to slack: https://api.slack.com/docs/message-formatting
    # slack converts the {date} and {time_secs} vars to local TZ.  if slack can't do that,
    # the UTC time is displayed instead.
    missing_msg = "Your AWS instance *{0}* in region *{1}* does not have the correct tags.  These tags are missing:\n*{2}*\n".format(name_msg, region, missing_tags)

    notify_msg = "\n*_If you do nothing, your instance will be shutdown on <!date^{0}^{{date}} at {{time_secs}}|{1} (UTC)>._*\n".format(time_for_next_action.timestamp, time_for_next_action)

    shutdown_msg = "\n*_If you do nothing, your instance will be terminated on <!date^{0}^{{date}} at {{time_secs}}|{1} (UTC)>._*\n".format(time_for_next_action.timestamp, time_for_next_action)

    terminate_msg = "\n_Your instance has been terminated._\n"

    if notification_type == 'notify':
        slack_msg = missing_msg + notify_msg
    elif notification_type == 'terminate':
        slack_msg = missing_msg + terminate_msg
    elif notification_type == 'shutdown':
        slack_msg = missing_msg + shutdown_msg

    slackit(instance_owner, slack_msg)

    return


def notify_channel(instance, region, notification_type, instance_name, missing_tags):
    logger.info("Notifying channel.")

    if dryrun:
        logger.debug("--dryrun flag was set so not doing anything")
        return

    if instance_name:
        name_msg = instance_name
    else:
        name_msg = '<blank>'

    slack_msg = "Name: *{0}* Instance: *{1}* Region: *{2}* Missing Tags: *{3}* Action: *{4}*".format(name_msg, instance.id, region, missing_tags, notification_type)

    slackit(slack_channel, slack_msg)


def shutdown_instance(instance, region):
    logger.info("Checking if we can shutdown instance {0}.".format(instance.id))

    if dryrun:
        logger.debug("--dryrun flag was set so not doing anything")
        return

    session = boto3.session.Session()
    ec2_client = session.resource('ec2', region)

    if not is_in_asg(instance.id, region):
        try:
            logger.info("Shutting down instance {0} because it isn't in an ASG.".format(instance.id))
            ec2_client.instances.filter(InstanceIds=[instance.id]).stop()
        except Exception as shutdown_exception:
            logger.warning("Error shutting down instance {0}:".format(instance.id))
            logger.warning("{0}".format(shutdown_exception))
        return
    else:
        logger.info("Instance {0} belongs to an ASG so we leave it alone for now.".format(instance.id))


def terminate_instance(instance, region):
    logger.info("Checking if we can terminate instance {0}.".format(instance.id))

    if dryrun:
        logger.debug("--dryrun flag was set so not doing anything")
        return

    session = boto3.session.Session()
    ec2_client = session.resource('ec2', region)

    if not is_in_asg(instance.id, region):
        try:
            logger.info("Terminating instance {0} because it isn't in an ASG.".format(instance.id))
            ec2_client.instances.filter(InstanceIds=[instance.id]).terminate()
        except Exception as terminate_exception:
            logger.warning("Error terminating instance {0}:".format(instance.id))
            logger.warning("{0}".format(terminate_exception))
        return
    else:
        logger.info("Instance {0} belongs to an ASG so we leave it alone for now.".format(instance.id))


def is_in_asg(instance, region):
    logger.info("Checking if instance {0} belongs to an ASG.".format(instance))
    asg_client = boto3.client('autoscaling', region_name=region)

    is_asg = asg_client.describe_auto_scaling_instances(InstanceIds=[instance])

    if is_asg.get('AutoScalingInstances'):
        return True
    else:
        return False


def get_date_object(date_string):
    return iso8601.parse_date(date_string)


def get_date_string(date_object):
    return rfc3339.rfc3339(date_object)


def main():
    parser = ArgumentParser()
    parser.add_argument('-f', '--find', action="store", choices=supported_types, help='Find misconfigured tags '
                                                             'by resource type.  Available Types: %s' % supported_types)
    parser.add_argument('-i', '--instance', action="store", help='Find misconfigured tags for instance')
    parser.add_argument('-r', '--region', action="store", help='AWS Region')
    parser.add_argument('-n', '--nowait', action="store_true", help='Disable wait so action can be taken now')
    parser.add_argument('-d', '--dryrun', action="store_true", help="Don't do anything destructive and don't notify")
    parser.add_argument('-l', '--log', action="store", default='INFO', choices=log_types, help='Logging verbosity.  '
                                                            'Available options: %s (default: INFO)' % log_types)

    args = parser.parse_args()

    global nowait
    global dryrun

    if args.log == 'DEBUG':
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    if args.nowait:
        nowait = True
    else:
        nowait = False

    if args.dryrun:
        dryrun = True
    else:
        dryrun = False

    if args.find in supported_types and args.find == 'ec2':
        if args.instance is None:
            target_instance = None
        else:
            target_instance = args.instance

        if args.region:
            target_region = [args.region]
        else:
            target_region = find_ec2_regions()
           # for region in find_ec2_regions():
           #     target_region = find_ec2_instances(region, target_instance)

    logger.debug("target_region: {0}".format(target_region))

    for region in target_region:
        for instance in find_ec2_instances(region, target_instance):
            if not get_instance_tag(instance, 'ha_tagoverlord_current_run'):
                first_run_tags(instance)

            current_run_timestamp_tag(instance, current_time)

            missing_tags = missing_tag(instance)

            if missing_tags == None:
                is_in_violation_now_tag(instance, 'no')
                next_action_tag(instance, 'notify')
                is_orphan_tag(instance, 'no')
            else:
                tag_overlord(instance, region, missing_tags)


if __name__ == "__main__":
    main()

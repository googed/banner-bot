from ConfigParser import SafeConfigParser
from datetime import datetime, timedelta
import HTMLParser
import logging, logging.config, re, sys, os
from time import time

from dateutil import parser, rrule, tz
import praw
from requests.exceptions import HTTPError
from sqlalchemy import create_engine
from sqlalchemy import Boolean, Column, DateTime, String, Text, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
import yaml

import random
import requests
from imgurpython import ImgurClient

# global reddit session
r = None
client_id = 'e4d4eef844f7b61'
client_secret = 'a52e7291b1bb2151b18492f8e46bb1a91344e57d'

client = ImgurClient(client_id, client_secret)

cfg_file = SafeConfigParser()
path_to_cfg = os.path.abspath(os.path.dirname(sys.argv[0]))
path_to_cfg = os.path.join(path_to_cfg, 'schedulebot.cfg')
cfg_file.read(path_to_cfg)

if cfg_file.get('database', 'system').lower() == 'sqlite':
    engine = create_engine(
        cfg_file.get('database', 'system')+':///'+\
        cfg_file.get('database', 'database'))
else:
    
    engine = create_engine(
        cfg_file.get('database', 'system')+'://'+\
        cfg_file.get('database', 'username')+':'+\
        cfg_file.get('database', 'password')+'@'+\
        cfg_file.get('database', 'host')+'/'+\
        cfg_file.get('database', 'database'))
    print "engine running..."
Base = declarative_base()
Session = sessionmaker(bind=engine, expire_on_commit=False)
session = Session()


class Subreddit(Base):

    """Table containing the subreddits for the bot to monitor.

    name - The subreddit's name. "gaming", not "/r/gaming".
    enabled - Subreddit schedule will not be executed if False
    schedule_yaml - YAML definition of the subreddit's schedule
    updated - Time that the subreddit was last updated (UTC)
    """

    __tablename__ = 'schedule'

    name = Column(Text, nullable=False, primary_key=True)
    enabled = Column(Integer, nullable=False, default=1)
    schedule_yaml = Column(Text)
    updated = Column(Integer, nullable=False)


class ScheduledEvent(object):
    _defaults = {'repeat': None,
                 'rrule': None,
                 'url': None,
                 'title': '#####Banners'}
    repeat_regex = re.compile(r'^(\d+)\s+(minute|hour|day|week|month|year)s?$')
    url_regex = re.compile(r'^https?:\/\/imgur\.com\/(a|gallery)\/\w+\/?$')
    freq_dict = {'minute': rrule.MINUTELY,
                'hour': rrule.HOURLY,
                 'day': rrule.DAILY,
                 'week': rrule.WEEKLY,
                 'month': rrule.MONTHLY,
                 'year': rrule.YEARLY,
                 }

    def __init__(self, values, default=None):
        values = lowercase_keys_recursively(values)

        # anything not defined in the "values" dict will be defaulted
        init = self._defaults.copy()
        init.update(values)

        # convert the dict to attributes
        self.__dict__.update(init)
        

        try:
            self.first = parser.parse(self.first)#, default=default)
            if not self.first.tzinfo:
                self.first = self.first.replace(tzinfo=tz.tzutc())
        except Exception as e:
            
            raise ValueError('Error parsing date from `first`.')

        try:
            if self.repeat:
                match = self.repeat_regex.match(self.repeat)
                interval = int(match.group(1))
                if interval == 0:
                    raise ValueError('Invalid repeat interval.')
                self.rrule = rrule.rrule(self.freq_dict[match.group(2)],
                                         interval=interval,
                                         dtstart=self.first)
                
            elif self.rrule:
                self.rrule = rrule.rrulestr(self.rrule, dtstart=self.first)
        except Exception as e:
            raise ValueError('Error parsing repeat interval.')

        self.title = self.replace_placeholders(self.title)
       

    def is_due(self, start_time, end_time):
        	
        if self.rrule:
            print "Due now? %s"	%(bool(self.rrule.between(start_time, end_time, inc=True))) 
            return bool(self.rrule.between(start_time, end_time, inc=True))
            			
        else:
            return start_time <= self.first <= end_time

    def execute(self, subreddit):
        global r
        IMAGE_COUNT = 5
        album_id = get_album_id(self.url)
        print album_id
        images = client.get_album_images(album_id)
        #images = images['data']
        if len(images) < IMAGE_COUNT:
            print('Not enough images!')
            return
     
        # Pick x random ones
        images = random.sample(images, IMAGE_COUNT)
        banner_number = 1
        sidebar_format = '* [{title}]({url} "{desc}")'
        sidebar_lines = []
        for image in images:
            url = image.link
            local_name = localize_name(album_id, url)
            download_image(url, local_name)
           
            title = image.title.replace('\n', '')
            description = image.description.replace('\n', '')
     
            line = sidebar_format.format(title=title, url=url, desc=description)
            sidebar_lines.append(line)
     
            css_name = 'banner%d' % banner_number
            print('Adding %s to stylesheet' % css_name)
            r.upload_image(subreddit, local_name, css_name)
     
            banner_number += 1
     
        bar = '\n'.join(sidebar_lines)
        current_sidebar = subreddit.get_settings()['description']
        current_sidebar = HTMLParser.HTMLParser().unescape(current_sidebar)
        new_sidebar = current_sidebar + bar
        r.update_settings(subreddit, description=new_sidebar)
            

        
    def replace_placeholders(self, string):
        date_regex = re.compile(r'\{\{date([+-]\d+)?\s+([^}]+?)\}\}')
        now = datetime.now(self.first.tzinfo)

        match = date_regex.search(string)
        while match:
            date = now
            if match.group(1):
                offset = int(match.group(1))
                date += timedelta(days=offset)
            format_str = match.group(2)
            string = date_regex.sub(date.strftime(format_str), string, count=1)
            match = date_regex.search(string)

        return string
    
def download_image(url, local_name):
    if os.path.exists(local_name):
        return
    location = os.path.split(local_name)[0]
    if not os.path.exists(location):
        os.makedirs(location)
    page = requests.get(url)
    image = page.content
    with open(local_name, 'wb') as f:
        f.write(image)
 
def localize_name(album_id, image_link):
    image_name = image_link.split('/')[-1]
    return os.path.join('images', album_id, image_name)
 
def get_album_id(album_url):
    album_url = album_url.replace('/gallery/', '/a/')
    album_id = album_url.split('/a/')[-1].split('/')[0]
    return album_id

def update_from_wiki(subreddit, requester):
    print "Updating events from the %s wiki." %subreddit
    global r
    username = cfg_file.get('reddit', 'username')

    try:
        
        page = subreddit.get_wiki_page(cfg_file.get('reddit', 'wiki_page_name'))
        
    except Exception:
            
        send_error_message(requester, subreddit.display_name,
            'The wiki page could not be accessed. Please ensure the page '
            'http://www.reddit.com/r/{0}/wiki/{1} exists and that {2} '
            'has the "wiki" mod permission to be able to access it.'
            .format(subreddit.display_name,
                    cfg_file.get('reddit', 'wiki_page_name'),
                    username))
        return False

    html_parser = HTMLParser.HTMLParser()
    page_content = html_parser.unescape(page.content_md)

    # check that all the events are valid yaml
    event_defs = yaml.safe_load_all(page_content)
    event_num = 1
    try:
        for event_def in event_defs:
            event_num += 1
    except Exception as e:
        indented = ''
        for line in str(e).split('\n'):
            indented += '    {0}\n'.format(line)
        send_error_message(requester, subreddit.display_name,
            'Error when reading schedule from wiki - '
            'Syntax invalid in section #{0}:\n\n{1}'
            .format(event_num, indented))
        return False
    
    # reload and actually process the events
    event_defs = yaml.safe_load_all(page_content)
    event_num = 1
    kept_sections = []
    for event_def in event_defs:
        # ignore any non-dict sections (can be used as comments, etc.)
        if not isinstance(event_def, dict):
            continue

        event_def = lowercase_keys_recursively(event_def)

        try:
            check_event_valid(event_def)
            event = ScheduledEvent(event_def)
        except ValueError as e:
            send_error_message(requester, subreddit.display_name,
                'Invalid event in section #{0} - {1}'
                .format(event_num, e))
            return False

        event_num += 1
        kept_sections.append(event_def)

    # Update the subreddit, or add it if necessary
    try:
        db_subreddit = (session.query(Subreddit)
                       .filter(Subreddit.name == subreddit.display_name.lower())
                       .one())
        
    except NoResultFound:
        db_subreddit = Subreddit()
        db_subreddit.name = subreddit.display_name.lower()
        session.add(db_subreddit)

    db_subreddit.updated = datetime.utcnow()
    db_subreddit.schedule_yaml = page_content
    session.commit()
    logging.info("Update complete")

    r.send_message(requester,
                   '{0} schedule updated'.format(username),
                   "{0}'s schedule was successfully updated for /r/{1}"
                   .format(username, subreddit.display_name))
    return True


def lowercase_keys_recursively(subject):
    """Recursively lowercases all keys in a dict."""
    lowercased = dict()
    for key, val in subject.iteritems():
        if isinstance(val, dict):
            val = lowercase_keys_recursively(val)
        lowercased[key.lower()] = val

    return lowercased


def check_event_valid(event):
    """Checks if an event defined on a wiki page is valid."""
    print "Validating wiki events..."	

    validate_keys(event)
    validate_values_not_empty(event)

    validate_type(event, 'first', basestring)
    validate_type(event, 'repeat', basestring)
    validate_type(event, 'rrule', basestring)
    validate_type(event, 'title', basestring)
    validate_regex(event, 'url', ScheduledEvent.url_regex)
    validate_regex(event, 'repeat', ScheduledEvent.repeat_regex)


def validate_values_not_empty(check):
    for key, val in check.iteritems():
        if isinstance(val, dict):
            validate_values_not_empty(val)
        elif (val is None or
              (isinstance(val, (basestring, list)) and len(val) == 0)):
            raise ValueError('`{0}` set to an empty value'.format(key))


def validate_keys(check):
    valid_keys = set(['first', 'rrule', 'title', 'url'])
    valid_keys |= set(ScheduledEvent._defaults.keys())
    for key in check:
        if key not in valid_keys:
            raise ValueError('Invalid variable: `{0}`'.format(key))

    # make sure that all of the required keys are being set
    if ('first' not in check or
            'url' not in check): #or 'text' not in check
        raise ValueError('All the required variables were not set.')


def validate_type(check, key, req_type):
    
    if key not in check:
        return

    if req_type == int:
        try:
            int(str(check[key]))
        except ValueError:
            raise ValueError('{0} must be an integer'.format(key))
    else:
        if not isinstance(check[key], req_type):
            raise ValueError('{0} must be {1}'.format(key, req_type))


def validate_regex(check, key, pattern):
    if key not in check:
        return

    if not re.match(pattern, check[key]):
        raise ValueError('Invalid {0}: {1}'.format(key, check[key]))


def send_error_message(user, sr_name, error):
    """Sends an error message to the user if a wiki update failed."""
    global r
    r.send_message(user,
                   'Error updating from wiki in /r/{0}'.format(sr_name),
                   '### Error updating from [wiki configuration in /r/{0}]'
                   '(http://www.reddit.com/r/{0}/wiki/{1}):\n\n---\n\n{2}'
                   .format(sr_name,
                           cfg_file.get('reddit', 'wiki_page_name'),
                           error))


def process_messages():
    
    global r
    
    stop_time = int(cfg_file.get('reddit', 'last_message'))

    owner_username = cfg_file.get('reddit', 'owner_username')
    new_last_message = None
    update_srs = set()
    invite_srs = set()

    logging.debug('Reading messages and commands...')

    try:
        for message in r.get_inbox():
            if int(message.created_utc) <= stop_time:
                break

            if message.was_comment:
                continue

            if not new_last_message:
                new_last_message = int(message.created_utc)

            if message.body.strip().lower() == 'schedule':
                # handle if they put in something like '/r/' in the subject
                if '/' in message.subject:
                    sr_name = message.subject[message.subject.rindex('/')+1:]
                else:
                    sr_name = message.subject

                if (sr_name.lower(), message.author.name) in update_srs:
                    continue

                try:
                    subreddit = r.get_subreddit(sr_name)
                    if (message.author.name == owner_username or
                            message.author in subreddit.get_moderators()):
                        update_srs.add((sr_name.lower(), message.author.name))
                    else:
                        send_error_message(message.author, sr_name,
                            'You do not moderate /r/{0}'.format(sr_name))
                except HTTPError as e:
                    send_error_message(message.author, sr_name,
                        'Unable to access /r/{0}'.format(sr_name))

        # do requested updates from wiki pages
        updated_srs = []
        for subreddit, sender in update_srs:
            if update_from_wiki(r.get_subreddit(subreddit),
                                r.get_redditor(sender)):
                updated_srs.append(subreddit)
                logging.info('Updated from wiki in /r/{0}'.format(subreddit))
            else:
                logging.info('Error updating from wiki in /r/{0}'
                             .format(subreddit))

    except Exception as e:
        logging.error('ERROR: {0}'.format(e))
        raise
    finally:
        # update cfg with new last_message value
        if new_last_message:
            cfg_file.set('reddit', 'last_message', str(new_last_message))
            cfg_file.write(open(path_to_cfg, 'w'))




 
def main():
    global r
    logging.config.fileConfig(path_to_cfg)

    start_timestamp = int(time())
    start_time = datetime.utcfromtimestamp(start_timestamp)
    start_time = start_time.replace(tzinfo=tz.tzutc())
    print "Start time %s" %start_time
    
    
    last_run = int(cfg_file.get('reddit', 'last_run'))
    last_run = datetime.utcfromtimestamp(last_run)
    last_run = last_run.replace(tzinfo=tz.tzutc())

    cfg_file.set('reddit', 'last_run', str(start_timestamp))
    cfg_file.write(open(path_to_cfg, 'w'))

    while True:
        try:
            r = praw.Reddit(user_agent=cfg_file.get('reddit', 'user_agent'))
            logging.debug('Logging in as {0}'
                          .format(cfg_file.get('reddit', 'username')))
            r.login(cfg_file.get('reddit', 'username'),
                    cfg_file.get('reddit', 'password'), disable_warning=True)
            
            
            break
            
        except Exception as e:
            		
            logging.error('ERROR: {0}'.format(e))

    # check for update messages
    logging.info("checking for update messages")
    try:
        process_messages()
    except KeyboardInterrupt:
        raise
    except Exception as e:
        logging.error('ERROR: {0}'.format(e))
        session.rollback()

    subreddits = (session.query(Subreddit)
                         .filter(Subreddit.enabled == 1)
                         .all())
    for sr in subreddits:
               	
        schedule = [ScheduledEvent(d, sr.updated)
                    for d in yaml.safe_load_all(sr.schedule_yaml)
                    if isinstance(d, dict)]
       
        for event in schedule:
            	
            try:
                if event.is_due(last_run, start_time):
                    event.execute(r.get_subreddit(sr.name))
                    
            except KeyboardInterrupt:
                raise
            except Exception as e:
                		 
                logging.error('ERROR in /r/{0}: {1}. Rolling back'.format(sr.name, e))
                
                session.rollback()



if __name__ == '__main__':
    main()

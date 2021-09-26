import signal
from contextlib import contextmanager
from IPython.terminal.embed import InteractiveShellEmbed
from bs4 import BeautifulSoup as bs
from bs4 import BeautifulSoup, SoupStrainer
import requests
from os.path import join
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from IPython.display import display, HTML
import matplotlib.pyplot as plt
import matplotlib.image as mpimg
from termcolor import colored
from IPython.display import IFrame
from IPython.core.display import display

INTERACTIVE = True
try:
    get_ipython()
except:
    get_ipython = InteractiveShellEmbed
    get_ipython().dummy_mode = True
    INTERACTIVE = False

def setup_ipython():

    interactive = True
    try:
        get_ipython()
    except:
        get_ipython = InteractiveShellEmbed
        get_ipython().dummy_mode = True
        interactive = False
        
    return get_ipython, interactive
    
def show_term(width=1200, height=500, relative_dir = '7_THM_CTF'):
    display(IFrame('http://192.168.1.21:8888/lab/tree/%s' % relative_dir, width=width, height=height))
    
def printr(text):
    print(colored(text, "red"))
          
class TimeoutException(Exception): pass

@contextmanager
def time_limit(seconds):
    def signal_handler(signum, frame):
        raise TimeoutException("Timed out!")
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)



class WebsiteRecord:
    def __init__(self, target, directory='', port=80, status = None):
        self.target = target
        self.directory = directory
        self.port=port
        self.website = 'http://'+target+":%s"%self.port+directory
        self.status = status
        self.whatweb_result = {"stdout" : None,
                              "finished": False}
        self.source_result = {"stdout" : None,
                              "finished": False}
        self.screenshot = None
        self.gobuster_result = {"stdout" : None,
                                "links" : [],
                              "finished": False}
        self.okadmin_result = {"stdout" : None,
                               "links" : [],
                              "finished": False}
        self.crawler_result = {"stdout" : None,
                                "links" : [],
                              "finished": False}
        self.wordcount_result = {"stdout" : None,
                                 "counts" : {},
                              "finished": False}
        
        options = webdriver.ChromeOptions()
        options.add_argument('--ignore-certificate-errors')
        options.add_argument("--headless")

        self.driver = webdriver.Chrome(chrome_options=options, executable_path="chromedriver")   

    def whatweb(self, verbose = True):
        if verbose:
            get_ipython().system('whatweb {self.website}')
            
        whatweb_out = get_ipython().getoutput('whatweb --colour=never {self.website}')
        
        self.whatweb_result["stdout"] = whatweb_out
        self.whatweb_result["finished"] = True
        
        if "200 OK" in whatweb_out:
            self.status = 200
        
        return whatweb_out

    def view_source(self, verbose = True):
        source = get_ipython().getoutput('curl -s {self.website}')
        pretty_source = bs(source.nlstr, features="lxml").prettify()
        if verbose:
            print(pretty_source)
        self.source_result["stdout"] = pretty_source
        self.source_result["finished"] = True
        
        return source

    def capture_website(self, verbose = True):

        self.driver.get(self.website)
        screenshot = self.driver.save_screenshot('tmp_screenshot.png')
        image = mpimg.imread("tmp_screenshot.png")
        self.screenshot = image
        
        if verbose:
            plt.rcParams["figure.figsize"] = (25,10)
            plt.imshow(image)

    def gobuster(self, wordlist = '/usr/share/dirb/wordlists/common.txt', extensions=False, verbose = True): 
        
        extension_list = ""
        if extensions:
            extension_list = "-x .asp,.aspx,.bat,.c,.cfm,.cgi,.com,.dll,.exe,.htm,.html,.inc,.jhtml,.jsa,.jsp,.log,.mdb,.nsf,.php,.phtml,.pl,.reg,.sh,.shtml,.sql,.txt,.xml,/"
            
        if verbose:
            get_ipython().system('gobuster dir -t 30 -r -u {self.website} {extension_list} --wordlist {wordlist} | tee gobuster_out.txt')
        else:
            get_ipython().system('gobuster dir -t 30 -r -u {self.website} {extension_list} --wordlist {wordlist} > gobuster_out.txt')

        self.gobuster_result['stdout'] = get_ipython().getoutput('cat gobuster_out.txt')

    def ffuf(self, wordlist = '/usr/share/dirb/wordlists/common.txt', extensions=False, verbose = True, timeout=10, threads=50): 
        extension_list = ""
        if extensions:
            extension_list = "-e .asp,.aspx,.bat,.c,.cfm,.cgi,.com,.dll,.exe,.htm,.html,.inc,.jhtml,.jsa,.jsp,.log,.mdb,.nsf,.php,.phtml,.pl,.reg,.sh,.shtml,.sql,.txt,.xml,/"
            
        get_ipython().system('ffuf -ic -noninteractive -timeout {timeout} -t {threads} -recursion {extension_list} -v -c -r -w {wordlist} -u {self.website}/FUZZ -o ffuf_out.json')
        
        
        
    def okadminfinder(self, verbose = True):
        website = self.website
        try:
            website = website.split('//')[1]
        except: pass

        get_ipython().system('cd okadminfinder3 && unbuffer python3 okadminfinder.py -u {website} | tee okadmin.txt')
        result = get_ipython().getoutput('cat okadminfinder3/okadmin.txt')
        links_only = get_ipython().getoutput('cat okadminfinder3/okadmin.txt | grep http')
        return result, links_only

    def nmap_http_battery(self, verbose = True):
        if len(self.directory) > 0:
            get_ipython().system('echo nmap -Pn -p %s --script=http-sitemap-generator $TARGET --script-args=http-sitemap-generator.url=%s' % (self.port, self.directory))
            get_ipython().system('nmap -Pn -p %s --script=http-sitemap-generator $TARGET --script-args=http-sitemap-generator.url=%s' % (self.port, self.directory))
            
            get_ipython().system('echo nmap -Pn -p %s --script=http-auth-finder $TARGET --script-args=http-auth-finder.url=%s' % (self.port, self.directory))
            get_ipython().system('nmap -Pn -p %s --script=http-auth-finder $TARGET --script-args=http-auth-finder.url=%s' % (self.port, self.directory))
            
            get_ipython().system('echo nmap -Pn -p %s --script=http-comments-displayer $TARGET --script-args=http-comments-displayer.url=%s' % (self.port, self.directory))
            get_ipython().system('nmap -Pn -p %s --script=http-comments-displayer $TARGET --script-args=http-comments-displayer.url=%s' % (self.port, self.directory))
            
            get_ipython().system('echo nmap -Pn -p %s --script=http-backup-finder $TARGET --script-args=http-backup-finder.url=%s' % (self.port, self.directory))
            get_ipython().system('nmap -Pn -p %s --script=http-backup-finder $TARGET --script-args=http-backup-finder.url=%s' % (self.port, self.directory))
        else:
            get_ipython().system('echo nmap -Pn -p %s --script=http-sitemap-generator $TARGET' % self.port)
            get_ipython().system('nmap -Pn -p %s --script=http-sitemap-generator $TARGET'% self.port)
            
            get_ipython().system('echo nmap -Pn -p %s --script=http-auth-finder $TARGET'% self.port)
            get_ipython().system('nmap -Pn -p %s --script=http-auth-finder $TARGET'% self.port)
            
            get_ipython().system('echo nmap -Pn -p %s --script=http-comments-displayer $TARGET'% self.port)
            get_ipython().system('nmap -Pn -p %s --script=http-comments-displayer $TARGET'% self.port)
            
            get_ipython().system('echo nmap -Pn -p %s --script=http-backup-finder $TARGET'% self.port)
            get_ipython().system('nmap -Pn -p %s --script=http-backup-finder $TARGET'% self.port)
    
    def fingerprint_page(self, do_whatweb=True, do_screencap=True, do_source=True, do_ffuf=True, verbose=True):
        print('fingerprinting', self.website)
        whatweb_out = screencap_out = source_out = gobuster_out = None

        if do_whatweb:
            printr("\n\nWhatweb:")
            whatweb_out = self.whatweb(verbose=verbose)
        
        if do_ffuf:
            printr("\n\nFfuf:")
            gobuster_out = self.ffuf(verbose=verbose)
            
        if do_source:
            printr("\n\nSource:")
            source_out = self.view_source(verbose=verbose)
            
        printr("\n\nNMAP:")
        self.nmap_http_battery()
        
        printr("\n\nWord Counts:")
        self.count_words()
        
        if do_screencap:
            printr("\n\nScreencap:")
            screencap_out = self.capture_website(verbose=verbose)
            
        return whatweb_out, screencap_out, gobuster_out, source_out
    
    def fingerprint_extended(self):
        
        printr("\n\nFfuf Extensions:")
        self.ffuf(extensions=True, timeout=5, threads=120)
        
        printr("\n\nFfuf Large:")
        self.ffuf('/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt', timeout=5, threads=120)
        
        printr("\n\nOkAdmin:")
        result, okadmin_links = self.okadminfinder()
    
    def get_links(self):
        page = requests.get(self.website)    
        data = page.text
        soup = BeautifulSoup(data, features="lxml")
        links = [link.get('href') for link in soup.find_all('a') if link.get('href')[0] != '?' and link.get('href')[0] != '#']
        final_links = []
        for link in links:
    #         print(link)
            if '?' in link:
                link = link.split('?')[0]
                if not link in final_links:
                    final_links.append(link)
            else:
                if not link in final_links:
                    final_links.append(link)
        return final_links

    def get_links_recursive(self):
        final_links = []
        other_links = []
        for link in self.get_links():
            if link[0] != '/':
                full_path = join(self.website,link)
                print(full_path)
                final_links.append(full_path)
                new_links, other_links = get_links_recursive(full_path)
                final_links += new_links
                other_links += other_links
            else:
                if len(link)>0:
                    other_links.append(link)

        final_links = list(set(final_links))
        other_links = list(set(other_links))

        return final_links, other_links

    def count_words(self):
        get_ipython().system('cd CeWL && unbuffer ./cewl.rb -c {self.website} | tee wordcount.txt')
        result = get_ipython().getoutput('cat CeWL/wordcount.txt')
        return result

class LinkRecorder:
    def __init__(self):
        self.links = []
        self.records = []
        
    def add(self, website, status = None):
        if not website in self.links:
            print("adding", website)
            self.links.append(website)
            wr = WebsiteRecord(website, self, status)
            self.records.add(wr)
        else:
            print("already added:", website)
        
        
def save_notebook():
    script = """
    this.nextElementSibling.focus();
    this.dispatchEvent(new KeyboardEvent('keydown', {key:'s', keyCode: 83, metaKey: true}));
    """
    display(HTML((
        '<img src onerror="{}" style="display:none">'
        '<input style="width:0;height:0;border:0">'
    ).format(script)))
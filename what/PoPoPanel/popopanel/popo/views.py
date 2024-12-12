from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.http import HttpResponse
import logging
import subprocess
from django.contrib import messages
import os
from django.views.decorators.http import require_POST
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_protect
from popo.models import Customer , Website
import time
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib.auth import authenticate, login, logout
from django.contrib.sessions.models import Session
from django.utils import timezone
from popo.models import User
from popo.models import Website
logger = logging.getLogger(__name__)
from django.shortcuts import render, get_object_or_404
import os
import pwd
import grp
import stat
from django.utils.timezone import datetime
from bs4 import BeautifulSoup
import subprocess
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from popo.models import Customer, Website,Database,Subdomain,Dbuserpass
from django.shortcuts import render, get_object_or_404
from popo.models import Website
import random
import string
from django.shortcuts import get_object_or_404, render
from popo.models import WordPressCredentials
import requests
from popo.models import Website, WordPressCredentials
from django.contrib.auth.decorators import login_required
import requests
import re
from bs4 import BeautifulSoup
import base64
import logging
import requests
from requests.exceptions import ConnectionError, Timeout
from bs4 import BeautifulSoup
from bs4 import BeautifulSoup
logger = logging.getLogger(__name__)
from django.shortcuts import render
from django.http import HttpResponse
import os
import zipfile
import requests
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse
import os
import zipfile
import subprocess
from django.shortcuts import render
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages

import subprocess
from django.shortcuts import render


# def view_access_logs(request):
#     log_file_path = "/home/jija/jija.com/logs/access.log"
#     try:
#         logs = subprocess.check_output(['tail', '-n', '10', log_file_path], text=True)
#     except Exception as e:
#         logs = f"Error reading logs: {e}"
#     return render(request, 'user/log.html', {'logs': logs})

from django.http import HttpResponse

from django.shortcuts import get_object_or_404, render
from django.http import HttpResponse


def view_access_logs(request, website_id):
    # Fetch the website based on the website_id
    website = get_object_or_404(Website, id=website_id)

    try:
        # Dynamically construct the path to the access log file
        log_path = f'/home/{website.ftp_username}/{website.website_name}/logs/access.log'
        with open(log_path, 'r') as file:
            logs = file.read()  # Read all logs content
        return HttpResponse(logs, content_type='text/plain')
    except FileNotFoundError:
        return HttpResponse("Access log file not found", status=404)


def view_error_logs(request, website_id):
    # Fetch the website based on the website_id
    website = get_object_or_404(Website, id=website_id)

    try:
        # Dynamically construct the path to the error log file
        log_path = f'/home/{website.ftp_username}/{website.website_name}/logs/error.log'
        with open(log_path, 'r') as file:
            logs = file.read()  # Read all logs content
        return HttpResponse(logs, content_type='text/plain')
    except FileNotFoundError:
        return HttpResponse("Error log file not found", status=404)


def logs(request, website_id):
    # Pass the website_id to the template
    website = get_object_or_404(Website, id=website_id)
    return render(request, 'user/log.html', {'website': website})

# from django.shortcuts import render
# import os

# from django.shortcuts import render, get_object_or_404
# import subprocess

# import os
# from django.shortcuts import render
# from django.http import HttpResponse

# def get_logs_for_domain(request, domain_name):
#     """
#     Finds the logs directory for the given domain and retrieves the content of either access.log or error.log.
#     """
#     def find_domain_logs(domain):
#         """
#         Finds the logs directory for the given domain.
#         """
#         for root, dirs, files in os.walk("/home/"):
#             if root.endswith(f"{domain}/logs"):
#                 return root
#         return None

#     def read_log_file(log_path):
#         """
#         Reads the content of the log file.
#         """
#         if os.path.exists(log_path) and os.path.isfile(log_path):
#             with open(log_path, "r") as file:
#                 return file.readlines()
#         return None

#     # Find the logs directory for the given domain name
#     log_dir = find_domain_logs(domain_name)

#     if not log_dir:
#         return HttpResponse(f"Error: Logs directory for domain '{domain_name}' not found!", status=404)

#     log_content = None
#     log_file_name = ""

#     if request.method == "POST":
#         # Get the user's choice for logs
#         log_choice = request.POST.get("log_choice")

#         if log_choice == "1":
#             log_file_name = "access.log"
#         elif log_choice == "2":
#             log_file_name = "error.log"
#         else:
#             return HttpResponse("Invalid log choice.", status=400)

#         log_path = os.path.join(log_dir, log_file_name)
#         log_content = read_log_file(log_path)

#         if not log_content:
#             return HttpResponse(f"Error: The log file '{log_file_name}' does not exist or is empty in '{log_dir}'!", status=404)

#     return render(request, "user/domain_logs.html", {
#         "log_dir": log_dir,
#         "log_file_name": log_file_name,
#         "log_content": log_content,
#         "domain_name": domain_name,
#     })

@login_required
def remove_subdomain(request, subdomain_id):
    subdomain = get_object_or_404(Subdomain, id=subdomain_id)
    website = subdomain.website
    try:
        print(f"Removing Apache virtual host configuration for {subdomain.subdomain_name}")
        apache_conf = f"/etc/apache2/sites-available/{subdomain.subdomain_name}.conf"
        result = subprocess.run(['sudo', 'rm', '-f', apache_conf], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"Apache config removed: {result.stdout.decode()}")
        if result.returncode != 0:
            raise Exception(f"Error removing Apache config: {result.stderr.decode()}")
        print(f"Removing DNS entry for {subdomain.subdomain_name}")
        
        result = subprocess.run(['sudo', 'sh', '-c', f"sed -i '/{subdomain.subdomain_name}/d' /etc/hosts"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"DNS entry removed: {result.stdout.decode()}")
        if result.returncode != 0:
            raise Exception(f"Error updating /etc/hosts: {result.stderr.decode()}")
        print(f"Removing directories for subdomain {subdomain.subdomain_name}")
       
        result = subprocess.run(['sudo', 'rm', '-rf', f'/home/{website.ftp_username}/{subdomain.subdomain_name}'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"Subdomain directories removed: {result.stdout.decode()}")
        if result.returncode != 0:
            raise Exception(f"Error removing subdomain directories: {result.stderr.decode()}")
        print(f"Removing FTP user {subdomain.subdomainftpuser}")
       
        result = subprocess.run(['sudo', 'userdel', '-r', subdomain.subdomainftpuser], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"FTP user removed: {result.stdout.decode()}")
        if result.returncode != 0:
            raise Exception(f"Error removing FTP user: {result.stderr.decode()}")

        print(f"Removing vsftpd user configuration for {subdomain.subdomainftpuser}")
       
        vsftpd_user_conf = f"/etc/vsftpd/user_conf/{subdomain.subdomainftpuser}.conf"
        result = subprocess.run(['sudo', 'rm', '-f', vsftpd_user_conf], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"vsftpd user config removed: {result.stdout.decode()}")
        if result.returncode != 0:
            raise Exception(f"Error removing vsftpd config: {result.stderr.decode()}")
        print(f"Removing PHP-FPM pool configuration for {subdomain.subdomain_name}")
       
        php_fpm_conf = f"/etc/php/{subdomain.php_version}/fpm/pool.d/{subdomain.subdomain_name}.conf"
        result = subprocess.run(['sudo', 'rm', '-f', php_fpm_conf], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"PHP-FPM pool config removed: {result.stdout.decode()}")
        if result.returncode != 0:
            raise Exception(f"Error removing PHP-FPM pool config: {result.stderr.decode()}")

        print(f"Disabling site {subdomain.subdomain_name}")
        
        result = subprocess.run(['sudo', 'a2dissite', f'{subdomain.subdomain_name}.conf'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"Site disabled: {result.stdout.decode()}")
        if result.returncode != 0:
            raise Exception(f"Error disabling site: {result.stderr.decode()}")

        print(f"Reloading Apache service")
        result = subprocess.run(['sudo', 'systemctl', 'reload', 'apache2'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"Apache reloaded: {result.stdout.decode()}")
        if result.returncode != 0:
            raise Exception(f"Error reloading Apache: {result.stderr.decode()}")

        print(f"Restarting PHP-FPM service for PHP version {subdomain.php_version}")
        result = subprocess.run(['sudo', 'systemctl', 'restart', f'php{subdomain.php_version}-fpm'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"PHP-FPM restarted: {result.stdout.decode()}")
        if result.returncode != 0:
            raise Exception(f"Error restarting PHP-FPM: {result.stderr.decode()}")

        subdomain.delete()

        messages.success(request, f'Subdomain {subdomain.subdomain_name} removed successfully.')
        return redirect('list_subdomain', website_id=website.id) 

    except subprocess.CalledProcessError as e:
        print(f"Error during subprocess execution: {e}")
        messages.error(request, f'Error while removing subdomain: Command failed with return code {e.returncode}. {e.stderr.decode()}')
    except Exception as e:
        print(f"General error: {e}")
        messages.error(request, f'Error while removing subdomain: {str(e)}')

    return redirect('website_info', id=website.id)

def list_subdomain(request, website_id):

    website = get_object_or_404(Website, id=website_id)   
    subdomains = Subdomain.objects.filter(website=website)
    print(f"Website: {website.website_name}, ID: {website.id}")
    print(f"Subdomains Count: {subdomains.count()}")
    for sub in subdomains:
        print(f"Subdomain: {sub.subdomain_name}, PHP Version: {sub.php_version}")

    return render(request, 'user/list_subdomain.html', {
        'website': website,
        'subdomains': subdomains
    })

@login_required
def remove_website(request):
    websites = Website.objects.all()  
    if request.method == 'POST':
        website_id = request.POST.get('website') 
        if website_id:
            return redirect('delete_website_action', website_id=website_id) 
    return render(request, 'user/remove_website.html', {'websites': websites})

def delete_database_and_user(ftp_username):
    with connection.cursor() as cursor:     
        cursor.execute("SELECT username, password FROM database_detials WHERE id = 1;")
        result = cursor.fetchone()
        if result:
            username, password = result
            print(f"Root Username: {username}")
            print(f"Root Password: {password}")
        else:
            raise RuntimeError("Database credentials not found in the database_detials table.")

    try:        
        db_record = Dbuserpass.objects.filter(ftp_username=ftp_username).first()
        if not db_record:
            raise RuntimeError(f"No database record found for FTP username: {ftp_username}")
        db_name = db_record.db_name
        db_user = db_record.db_user
        mysql_command = ['mysql', '-u', username, f'-p{password}']

        result = subprocess.run(
            mysql_command + ['-e', f"DROP DATABASE IF EXISTS {db_name};"],
            check=True, capture_output=True, text=True
        )
        print("Drop Database Output:", result.stdout)

        result = subprocess.run(
            mysql_command + ['-e', f"DROP USER IF EXISTS '{db_user}'@'localhost';"],
            check=True, capture_output=True, text=True
        )
        print("Drop User Output:", result.stdout)
       
        result = subprocess.run(
            mysql_command + ['-e', "FLUSH PRIVILEGES;"],
            check=True, capture_output=True, text=True
        )
        print("Flush Privileges Output:", result.stdout)

        db_record.delete()
        print("Database information deleted successfully from Dbuserpass.")

    except subprocess.CalledProcessError as e:
        error_message = e.stderr if e.stderr else str(e)
        raise RuntimeError(f"An error occurred while deleting the database and user: {error_message}")


def delete_all_subdomains(request, website):
    print(f"Starting deletion of all subdomains for website: {website.website_name}")
    subdomains = website.subdomain_set.all()  
    
    for subdomain in subdomains:
        subdomain_name = subdomain.subdomain_name
        php_version = subdomain.php_version
        ftp_username = subdomain.subdomainftpuser
        print(f"Deleting subdomain: {subdomain_name}, PHP version: {php_version}, FTP username: {ftp_username}")
        
        try:
            apache_conf = f"/etc/apache2/sites-available/{subdomain_name}.conf"
            print(f"Apache config path: {apache_conf}")

            sites_conf = f"/etc/apache2/sites-enabled/{subdomain_name}.conf"
            print(f"Apache config path: {sites_conf}")
            
            php_fpm_conf = f"/etc/php/{php_version}/fpm/pool.d/{subdomain_name}.conf"
            print(f"PHP-FPM config path: {php_fpm_conf}")
            
            vsftpd_user_conf = f"/etc/vsftpd/user_conf/{ftp_username}.conf"
            print(f"Vsftpd user config path: {vsftpd_user_conf}")

            subprocess.run(['sudo', 'a2dissite', f'{subdomain_name}.conf'], check=True)
            print(f"Disabled Apache site for subdomain: {subdomain_name}")
            
            subprocess.run(['sudo', 'rm','-rf', apache_conf], check=True)
            print(f"Removed Apache config for subdomain: {subdomain_name}")

            subprocess.run(['sudo', 'rm', sites_conf], check=True)
            print(f"Removed Sites Enabled Apache config for subdomain: {subdomain_name}")

            subprocess.run(['sudo', 'systemctl', 'reload', 'apache2'], check=True)
            print("Reloaded Apache after subdomain deletion")

            subprocess.run(['sudo', 'systemctl', 'stop', f'php{php_version}-fpm'], check=True)
            print(f"Stopped PHP-FPM service for PHP version: {php_version}")

            subprocess.run(['sudo', 'rm', '-rf', php_fpm_conf], check=True)
            print(f"Removed PHP-FPM config for subdomain: {subdomain_name}")

            subprocess.run(['sudo', 'systemctl', 'start', f'php{php_version}-fpm'], check=True)
            print(f"Restarted PHP-FPM service for PHP version: {php_version}")

            # Remove entry from /etc/hosts
            # subprocess.run(f'sudo sed -i "/{subdomain_name}/d" /etc/hosts', shell=True, check=True)
            # print(f"Removed {subdomain_name} from /etc/hosts")

            if os.path.exists(vsftpd_user_conf):
                subprocess.run(['sudo', 'rm', vsftpd_user_conf], check=True)
                print(f"Removed vsftpd user config for FTP user: {ftp_username}")

            subdomain.delete()
            print(f"Subdomain {subdomain_name} deleted successfully.")

        except subprocess.CalledProcessError as e:
            print(f"Error deleting subdomain {subdomain_name}: {e.stderr.decode() if e.stderr else str(e)}")
            messages.error(request, f'Error deleting subdomain {subdomain_name}: {str(e)}')
        except Exception as e:
            print(f"Unexpected error: {str(e)}")
            messages.error(request, f'Unexpected error deleting subdomain {subdomain_name}: {str(e)}')

    print(f"All subdomains for website {website.website_name} deleted successfully.")
    messages.success(request, f"All subdomains for website {website.website_name} deleted successfully.")

@login_required
def delete_website_action(request, website_id):
    print(f"Starting deletion of website with ID: {website_id}")
    website = get_object_or_404(Website, id=website_id)
    ftp_username = website.ftp_username
    website_name = website.website_name
    php_version = website.php_version  
    print(f"Website details - Name: {website_name}, FTP Username: {ftp_username}, PHP Version: {php_version}")

    try:
        # Delete all subdomains first
        delete_all_subdomains(request, website)
        
        
        apache_conf = f"/etc/apache2/sites-available/{website_name}.conf"
        php_fpm_conf = f"/etc/php/{php_version}/fpm/pool.d/{ftp_username}.conf"
        vsftpd_user_conf = f"/etc/vsftpd/user_conf/{ftp_username}"
        print(f"Paths - Apache Config: {apache_conf}, PHP-FPM Config: {php_fpm_conf}, Vsftpd Config: {vsftpd_user_conf}")

        # Disable and remove main Apache config
        subprocess.run(['sudo', 'a2dissite', f'{website_name}.conf'], check=True)
        print(f"Disabled Apache site for main website: {website_name}")
        
        subprocess.run(['sudo', 'rm', apache_conf], check=True)
        print(f"Removed Apache config for main website: {website_name}")

        subprocess.run(['sudo', 'systemctl', 'reload', 'apache2'], check=True)
        print("Reloaded Apache after main website deletion")

        
        subprocess.run(['sudo', 'systemctl', 'stop', f'php{php_version}-fpm'], check=True)
        print(f"Stopped PHP-FPM service for PHP version: {php_version}")

        subprocess.run(['sudo', 'rm', '-rf', php_fpm_conf], check=True)
        print(f"Removed PHP-FPM config for main website: {website_name}")

        subprocess.run(['sudo', 'systemctl', 'start', f'php{php_version}-fpm'], check=True)
        print(f"Restarted PHP-FPM service for PHP version: {php_version}")

        # Remove main website entry from /etc/hosts
        # subprocess.run(f'sudo sed -i "/{website_name}/d" /etc/hosts', shell=True, check=True)
        # print(f"Removed {website_name} from /etc/hosts")

        delete_database_and_user(ftp_username)
        print(f"Database and user {ftp_username} deleted")

        if os.path.exists(vsftpd_user_conf):
            subprocess.run(['sudo', 'rm', vsftpd_user_conf], check=True)
            print(f"Removed vsftpd user config for FTP user: {ftp_username}")
 
        subprocess.run(['sudo', 'systemctl', 'stop', f'php{php_version}-fpm'], check=True)
        print(f"Stopped PHP-FPM service for PHP version: {php_version}")
        

        subprocess.run(['sudo', 'userdel', '-r', ftp_username],  check=True)
        print(f"Deleted system user for FTP: {ftp_username}")

        subprocess.run(['sudo', 'systemctl', 'stop', f'php{php_version}-fpm'], check=True)
        print(f"Stopped PHP-FPM service for PHP version: {php_version}")

        # Delete main website from database
        website.delete()
        print(f"Website {website_name} deleted from database")
        messages.success(request, f'Website {website_name} and user {ftp_username} along with all subdomains deleted successfully.')

    except subprocess.CalledProcessError as e:
        error_message = e.stderr.decode() if e.stderr else str(e)
        print(f"Error during deletion: {error_message}")
        messages.error(request, f'Error during deletion: {error_message}')
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        messages.error(request, f'Unexpected error: {str(e)}')

    print(f"Redirection to list_websites")
    return redirect('list_websites')


# @login_required
# def delete_website_action(request, website_id):
#     website = get_object_or_404(Website, id=website_id)
#     ftp_username = websit e.ftp_username
#     website_name = website.website_name
#     php_version = website.php_version  

#     try:
#         # Define paths for Apache, PHP, and vsftpd configuration files
#         apache_conf = f"/etc/apache2/sites-available/{website_name}.conf"
#         php_fpm_conf = f"/etc/php/{php_version}/fpm/pool.d/{ftp_username}.conf"
#         vsftpd_user_conf = f"/etc/vsftpd/user_conf/{ftp_username}"

#         # Remove Apache configuration
#         subprocess.run(['sudo', 'a2dissite', f'{website_name}.conf'], check=True)
#         subprocess.run(['sudo', 'rm', apache_conf], check=True)
#         subprocess.run(['sudo', 'systemctl', 'reload', 'apache2'], check=True)

#         # Remove PHP-FPM configuration
#         subprocess.run(['sudo', 'systemctl', 'stop', f'php{php_version}-fpm'], check=True)
#         subprocess.run(['sudo', 'rm', '-rf', php_fpm_conf], check=True)
#         subprocess.run(['sudo', 'systemctl', 'start', f'php{php_version}-fpm'], check=True)

#         # Remove FTP user configuration and delete the user
#         if os.path.exists(vsftpd_user_conf):
#             subprocess.run(['sudo', 'rm', vsftpd_user_conf], check=True)
#         subprocess.run(['sudo', 'userdel', '-r', ftp_username], check=True)

#         # Remove entry from /etc/hosts
#         subprocess.run(f'sudo sed -i "/{website_name}/d" /etc/hosts', shell=True, check=True)

#         delete_database_and_user(ftp_username)

#         # Delete the website entry from the database
#         website.delete()

#         # Display success message
#         messages.success(request, f'Website {website_name} and user {ftp_username} deleted successfully.')

#     except subprocess.CalledProcessError as e:
#         error_message = e.stderr.decode() if e.stderr else str(e)
#         messages.error(request, f'Error during deletion: {error_message}')
#     except Exception as e:
#         messages.error(request, f'Unexpected error: {str(e)}')

#     return redirect('list_websites')

# @login_required
# def delete_website_action(request, website_id):
#     website = get_object_or_404(Website, id=website_id)
#     ftp_username = website.ftp_username
#     website_name = website.website_name
#     php_version = website.php_version  

#     try:

#         apache_conf = f"/etc/apache2/sites-available/{website_name}.conf"
#         php_fpm_conf = f"/etc/php/{php_version}/fpm/pool.d/{ftp_username}.conf" 
#         subprocess.run(['sudo', 'rm', apache_conf], check=True) 
#         subprocess.run(['sudo', 'a2dissite', f'{website_name}.conf'], check=True)
#         subprocess.run(['sudo', 'systemctl', 'reload', 'apache2'], check=True)

#         subprocess.run(['sudo', 'systemctl', 'stop', f'php{php_version}-fpm'], check=True)
#         subprocess.run(['sudo', 'rm', '-rf', php_fpm_conf], check=True)
#         subprocess.run(['sudo', 'userdel', '-r', ftp_username], check=True)
#         subprocess.run(['sudo', 'systemctl', 'start', f'php{php_version}-fpm'], check=True)
        
#         subprocess.run(f'sudo sed -i "/{website_name}/d" /etc/hosts', shell=True, check=True)

#         website.delete()

#         messages.success(request, f'Website {website_name} and user {ftp_username} deleted successfully.')
#     except subprocess.CalledProcessError as e:
        
#         error_message = e.stderr.decode() if e.stderr else str(e)
#         messages.error(request, f'Error during deletion: {error_message}')
#     except Exception as e:
        
#         messages.error(request, f'Unexpected error: {str(e)}')

#     return redirect('list_websites') 


def upload_file(request, website_id):
    if request.method == 'POST':
        zip_file = request.FILES.get('zip_file')

        if zip_file and zip_file.name.endswith('.zip'):
            # Get the specific Website instance using the provided website_id
            website = get_object_or_404(Website, id=website_id)
            ftp_username = website.ftp_username
            website_name = website.website_name
            
            # Construct the upload path
            upload_path = f'/home/{ftp_username}/{website_name}/public_html/wp-content/plugins'
            zip_file_path = os.path.join(upload_path, zip_file.name)

            # Save the uploaded ZIP file
            with open(zip_file_path, 'wb+') as destination:
                for chunk in zip_file.chunks():
                    destination.write(chunk)

            try:
                with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                    # Check if it contains valid WordPress plugin structure
                    valid_plugin = False
                    for file_info in zip_ref.infolist():
                        if file_info.filename.endswith('.php'):
                            # Check for a valid plugin header in the first PHP file
                            with zip_ref.open(file_info) as php_file:
                                content = php_file.read(2048).decode('utf-8', errors='ignore')
                                if 'Plugin Name:' in content:
                                    valid_plugin = True
                                    break

                    if not valid_plugin:
                        os.remove(zip_file_path)  # Clean up the uploaded zip file
                        print(f"The uploaded ZIP file is not a valid WordPress plugin")
                        return HttpResponse("The uploaded ZIP file is not a valid WordPress plugin.")
 
                    # Extract the contents if it is a valid plugin
                    zip_ref.extractall(upload_path)

                # List all directories in the upload path after extraction
                extracted_folders = [f for f in os.listdir(upload_path) 
                                     if os.path.isdir(os.path.join(upload_path, f))]

                if not extracted_folders:
                    print(f"The uploaded ZIP file does not contain any directories.")
                    return HttpResponse("The uploaded ZIP file does not contain any directories.")

                # Run WP-CLI to activate the plugin
                try:
                    wp_cli_command = f"wp plugin activate {extracted_folders[0]} --path=/home/{ftp_username}/{website_name}/public_html   --allow-root"
                    subprocess.run(wp_cli_command, shell=True, check=True)
                    print(f"wp plugin activate")

                    # Optional: Delete the zip file after extraction
                    os.remove(zip_file_path)

                    # Redirect to the user/wordpress_user.html after success
                    return redirect('wordpress_user', website_id=website_id)

                except subprocess.CalledProcessError as e:
                    return HttpResponse(f"Plugin uploaded and extracted, but activation failed: {str(e)}")
            except zipfile.BadZipFile:
                return HttpResponse("The uploaded file is not a valid ZIP file.")
            except Exception as e:
                return HttpResponse(f"An error occurred while extracting the file: {str(e)}")
        else:
            return HttpResponse("Please upload a valid ZIP file.")
    return render(request, 'user/wordpress_user.html')

@csrf_exempt  # Allow CSRF exemption for this view
def toggle_plugin(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            plugin_name = data.get('plugin')
            action = data.get('action')
            website_id = data.get('website_id')
            website = get_object_or_404(Website, id=website_id)
            ftp_username = website.ftp_username
            website_name = website.website_name
        
            path = f'/home/{ftp_username}/{website_name}/public_html'
      
            command = ['wp', 'plugin', action, plugin_name, '--path=' + path, '--allow-root']
         
            result = subprocess.run(command, capture_output=True, text=True)

            if result.returncode == 0:
                return JsonResponse({'success': True})
            else:
                return JsonResponse({'success': False, 'error': result.stderr.strip()})

        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})

    return JsonResponse({'success': False, 'error': 'Invalid request method.'})


@csrf_exempt
def list_plugins(request, website_id):
    # Fetch website details using website_id
    website = get_object_or_404(Website, id=website_id)
    ftp_username = website.ftp_username
    website_name = website.website_name

    # Construct the path to the WordPress installation
    wp_path = f'/home/{ftp_username}/{website_name}/public_html'
    print(f'WP Path: {wp_path}')  # Debug statement for logging the path

    try:
        # Run the wp-cli command to list plugins
        result = subprocess.run(
            ['wp', 'plugin', 'list', f'--path={wp_path}', '--format=json', '--allow-root'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        # Parse the JSON output from the wp-cli command
        plugins_info = json.loads(result.stdout)

        return JsonResponse({'plugins': plugins_info})

    except FileNotFoundError:
        return JsonResponse({'error': 'Plugins directory not found.'}, status=404)
    
    except subprocess.CalledProcessError as e:
        # Handle errors from the wp-cli command and decode the error message
        error_message = e.stderr.decode('utf-8')
        return JsonResponse({'error': error_message}, status=500)





import subprocess
import json
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
import subprocess
import json
from .models import Website

from django.http import JsonResponse
from django.shortcuts import get_object_or_404
import subprocess
import json
from .models import Website  # Adjust the import based on your project structure


def search_plugin(request, website_id):
    query = request.GET.get('query', '')  # Get the search query
    plugins = []

    if query and website_id:
        try:
            # Fetch the website information from the database
            website = get_object_or_404(Website, id=website_id)
            ftp_username = website.ftp_username
            website_name = website.website_name

            # Dynamically construct the WordPress path
            wordpress_path = f'/home/{ftp_username}/{website_name}/public_html'

            # Log the path and query for debugging
            logger.info(f"WordPress Path: {wordpress_path}")
            logger.info(f"Query: {query}")

            # Execute the wp plugin search command
            result = subprocess.run(
                ['wp', 'plugin', 'search', query, '--path=' + wordpress_path, '--format=json', '--allow-root'],
                capture_output=True, text=True, check=True
            )
            logger.info(f"WP-CLI Output: {result.stdout}")

            # Parse the plugins JSON output
            plugins_data = json.loads(result.stdout)
            plugins = [
                {"name": plugin.get('name'), "slug": plugin.get('slug'), "rating": plugin.get('rating')}
                for plugin in plugins_data
            ]
        except subprocess.CalledProcessError as e:
            logger.error(f"WP-CLI Error: {e.stderr}")
            return JsonResponse({'error': f"Error executing WP-CLI: {e.stderr}"})
        except Exception as e:
            logger.error(f"Unexpected Error: {str(e)}")
            return JsonResponse({'error': str(e)})

    return JsonResponse({'plugins': plugins})


# def search_plugin(request, website_id):  # Ensure website_id is included in the parameters
#     query = request.GET.get('query', '')  # Get the search query
#     plugins = []

#     if query and website_id:
#         try:
#             # Fetch the website information from the database
#             website = get_object_or_404(Website, id=website_id)
#             ftp_username = website.ftp_username
#             website_name = website.website_name

#             # Dynamically construct the WordPress path
#             wordpress_path = f'/home/{ftp_username}/{website_name}/public_html'

#             # Execute the wp plugin search command with dynamic path and --allow-root
#             result = subprocess.run(
#                 ['wp', 'plugin', 'search', query, '--path=' + wordpress_path, '--format=json', '--allow-root'],
#                 capture_output=True, text=True, check=True
#             )
#             plugins_data = result.stdout

#             # Parse the plugins JSON output from WP-CLI
#             plugins = [
#                 {"name": plugin.get('name'), "slug": plugin.get('slug'), "rating": plugin.get('rating')}
#                 for plugin in json.loads(plugins_data)
#             ]
#         except subprocess.CalledProcessError as e:
#             return JsonResponse({'error': f"Error executing WP-CLI: {e.stderr}"})
#         except Exception as e:
#             return JsonResponse({'error': str(e)})

#     # Return the plugin results as JSON
#     return JsonResponse({'plugins': plugins})

import json
from django.views.decorators.csrf import csrf_exempt
import logging
import subprocess

logger = logging.getLogger(__name__)

@csrf_exempt
def install_plugin(request, website_id): 
    if request.method == 'POST':
        try:
            body = json.loads(request.body)
            slug = body.get('slug', '')

            if slug:
                # Log slug received from the request
                logger.info(f"Received plugin slug: {slug}")

                # Fetch the website information from the database
                website = get_object_or_404(Website, id=website_id)
                wordpress_path = f'/home/{website.ftp_username}/{website.website_name}/public_html'
                
                # Log WordPress path and website details    
                logger.info(f"Installing plugin for website: {website.website_name} at {wordpress_path}")

                # Run the WP-CLI plugin install command
                command = [
                    'wp', 'plugin', 'install', slug,
                    '--path=' + wordpress_path, '--activate', '--allow-root'
                ]
                logger.info(f"Running command: {' '.join(command)}")
                result = subprocess.run(command, capture_output=True, text=True)

                # Log command output
                logger.info(f"Command stdout: {result.stdout.strip()}")
                logger.error(f"Command stderr: {result.stderr.strip()}") if result.returncode != 0 else None

                # Check if the command executed successfully
                if result.returncode == 0:
                    logger.info(f"Plugin {slug} installed successfully.")
                    return JsonResponse({'success': True, 'message': f'Plugin {slug} installed successfully!'})
                else:
                    logger.error(f"Failed to install {slug}: {result.stderr.strip()}")
                    return JsonResponse({'success': False, 'message': f'Failed to install {slug}: {result.stderr.strip()}'})
            else:
                logger.warning("No slug provided in the request.")
                return JsonResponse({'success': False, 'message': 'No slug provided.'})

        except Exception as e:
            logger.exception("An error occurred while installing the plugin.")
            return JsonResponse({'success': False, 'message': str(e)})

    logger.warning("Invalid request method received.")
    return JsonResponse({'success': False, 'message': 'Invalid request.'})

import subprocess
import json
import logging
import json
import subprocess
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)  # Use the module-level logger

@csrf_exempt
def search_themes(request, website_id):
    if request.method == 'GET':
        query = request.GET.get('query', '')
        themes = []
        
        # Fetch website details
        website = get_object_or_404(Website, id=website_id)
        wordpress_path = f'/home/{website.ftp_username}/{website.website_name}/public_html'
        
        logger.info(f"Starting theme search. Query: '{query}', WordPress Path: '{wordpress_path}'")
        
        if query:
            try:
                # Run the WP-CLI command to search for themes
                logger.debug("Executing WP-CLI theme search command.")
                result = subprocess.run(
                    ['wp', 'theme', 'search', query, '--path=' + wordpress_path, '--format=json' , '--allow-root'],
                    capture_output=True, text=True, check=True
                )
                themes_data = result.stdout
                logger.debug(f"WP-CLI output: {themes_data}")

                # Parse the themes JSON output from WP-CLI
                themes = [
                    {"name": theme.get('name'), "slug": theme.get('slug'), "rating": theme.get('rating')}
                    for theme in json.loads(themes_data)
                ]
                logger.info(f"Found {len(themes)} themes matching query '{query}'.")
            except subprocess.CalledProcessError as e:
                logger.error(f"WP-CLI command failed: {e.stderr}")
                return JsonResponse({'error': f"Error executing WP-CLI: {e.stderr}"})
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding WP-CLI output: {str(e)}")
                return JsonResponse({'error': 'Invalid WP-CLI output format.'})
            except Exception as e:
                logger.exception(f"Unexpected error during theme search: {str(e)}")
                return JsonResponse({'error': str(e)})

        # Return the themes as JSON response
        return JsonResponse({'themes': themes})

    logger.warning("Invalid request method for search_themes.")
    return JsonResponse({'error': 'Invalid request method'})


import subprocess
import json

from django.views.decorators.csrf import csrf_exempt

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Website  
import json
import subprocess
import os


@csrf_exempt
def install_theme(request, website_id):
    if request.method == 'POST':
        try:
            # Parse the request body
            body = json.loads(request.body)
            slug = body.get('slug', '')
            logger.info(f'Received slug: "{slug}"')
            
            if not slug:
                logger.warning('No slug provided in the request.')
                return JsonResponse({'success': False, 'error': 'No slug provided.'})

            try:
                # Fetch website details
                website = Website.objects.get(id=website_id)
                wp_path = f'/home/{website.ftp_username}/{website.website_name}/public_html'
                logger.info(f'WordPress path: {wp_path}')
                
                # Validate WordPress installation
                if not os.path.exists(os.path.join(wp_path, 'wp-config.php')):
                    logger.error(f'Invalid WordPress installation at path: {wp_path}')
                    return JsonResponse({'success': False, 'error': 'Invalid WordPress installation at the specified path.'})
            except Website.DoesNotExist:
                logger.error(f'Website with ID {website_id} not found.')
                return JsonResponse({'success': False, 'error': 'Website not found.'})

            # Check existing themes
            check_command = [
                'wp', 'theme', 'list', '--path=' + wp_path, '--allow-root'
            ]
            check_result = subprocess.run(check_command, capture_output=True, text=True)
            logger.debug(f'Existing themes:\n{check_result.stdout.strip()}')

            # Install and activate theme
            command = [
                'wp', 'theme', 'install', slug,
                '--path=' + wp_path,
                '--activate',
                '--allow-root'
            ]
            logger.info(f'Executing command: {" ".join(command)}')

            result = subprocess.run(command, capture_output=True, text=True)
            logger.debug(f'STDOUT: {result.stdout.strip()}')
            logger.debug(f'STDERR: {result.stderr.strip()}')

            # Process result
            if result.returncode == 0:
                logger.info(f'Theme "{slug}" installed and activated successfully.')
                return JsonResponse({'success': True, 'message': f'Theme "{slug}" installed and activated successfully.'})
            else:
                logger.error(f'Error installing theme: {result.stderr.strip()}')
                return JsonResponse({'success': False, 'error': result.stderr.strip()})

        except json.JSONDecodeError:
            logger.error('Invalid JSON received in the request body.')
            return JsonResponse({'success': False, 'error': 'Invalid JSON received.'})

        except Exception as e:
            logger.exception(f'An unexpected exception occurred: {str(e)}')
            return JsonResponse({'success': False, 'error': str(e)})

    logger.warning('Invalid request method or no slug provided.')
    return JsonResponse({'success': False, 'error': 'Invalid request'})

import os
import zipfile
import subprocess
from django.shortcuts import get_object_or_404, redirect
from django.http import HttpResponse
from .models import Website  # Adjust import based on your project structure

def upload_theme(request, website_id):
    if request.method == 'POST':
        theme_zip = request.FILES.get('theme_zip')

        if theme_zip and theme_zip.name.endswith('.zip'):
            # Get the specific Website instance using the provided website_id
            website = get_object_or_404(Website, id=website_id)
            ftp_username = website.ftp_username
            website_name = website.website_name
            
            # Construct the upload path
            upload_path = f'/home/{ftp_username}/{website_name}/public_html/wp-content/themes'
            zip_file_path = os.path.join(upload_path, theme_zip.name)

            # Save the uploaded ZIP file
            try:
                with open(zip_file_path, 'wb+') as destination:
                    for chunk in theme_zip.chunks():
                        destination.write(chunk)
            except PermissionError:
                return HttpResponse("Permission denied: Unable to save the ZIP file. Please check the folder permissions.")

            try:
                with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                    # Check if it contains a valid WordPress theme structure
                    valid_theme = False
                    for file_info in zip_ref.infolist():
                        if 'style.css' in file_info.filename:
                            valid_theme = True
                            break

                    if not valid_theme:
                        os.remove(zip_file_path)  # Clean up the uploaded zip file
                        return HttpResponse("The uploaded ZIP file is not a valid WordPress theme.")

                    # Extract the contents if it is a valid theme
                    zip_ref.extractall(upload_path)

                # List all directories in the upload path after extraction
                extracted_folders = [f for f in os.listdir(upload_path)
                                     if os.path.isdir(os.path.join(upload_path, f))]

                if not extracted_folders:
                    return HttpResponse("The uploaded ZIP file does not contain any directories.")

                # Run WP-CLI to activate the theme
                try:
                    wp_cli_command = f"wp theme activate {extracted_folders[0]} --path=/home/{ftp_username}/{website_name}/public_html --allow-root"
                    subprocess.run(wp_cli_command, shell=True, check=True)

                    # Optional: Delete the zip file after extraction
                    os.remove(zip_file_path)

                    # Redirect to the user/wordpress_user.html after success
                    return redirect('wordpress_user', website_id=website_id)

                except subprocess.CalledProcessError as e:
                    return HttpResponse(f"Theme uploaded and extracted, but activation failed: {str(e)}")
            except zipfile.BadZipFile:
                return HttpResponse("The uploaded file is not a valid ZIP file.")
            except Exception as e:
                return HttpResponse(f"An error occurred while extracting the file: {str(e)}")
        else:
            return HttpResponse("Please upload a valid ZIP file.")
    return render(request, 'user/wordpress_user.html')


def list_themes(request, website_id):
    try:
        print("Fetching website details using website_id...")  # Step 1
        # Fetch website details using website_id
        website = get_object_or_404(Website, id=website_id)
        ftp_username = website.ftp_username
        website_name = website.website_name
        print(f"Website fetched: {website_name}, FTP User: {ftp_username}")  # Step 2

        # Construct the dynamic path to the WordPress installation
        wp_path = f'/home/{ftp_username}/{website_name}/public_html'
        print(f"WordPress path constructed: {wp_path}")  # Step 3

        # Check if the path exists before running wp-cli
        if not os.path.exists(wp_path):
            print(f"Path does not exist: {wp_path}")  # Step 4
            return JsonResponse({'error': 'WordPress path does not exist.'}, status=404)
        print(f"WordPress path exists: {wp_path}")  # Step 5

        # Command to list themes with wp-cli
        wp_cli_command = [
            'wp', 'theme', 'list',
            f'--path={wp_path}',
            '--allow-root', '--format=json'
        ]
        print(f"Executing wp-cli command: {' '.join(wp_cli_command)}")  

        # Execute the command and capture the output
        result = subprocess.run(wp_cli_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"Command executed with return code: {result.returncode}")  # Step 7

        # If there is an error, log it and return the error
        if result.returncode != 0:
            print(f"Error in command: {result.stderr}")  # Step 8
            return JsonResponse({'error': f"Command failed: {result.stderr}"}, status=500)

        print("Parsing the JSON output from wp-cli...")  # Step 9
        # Parse the JSON output
        themes = json.loads(result.stdout)
        print(f"Parsed themes: {themes}")  # Step 10

        # Return the themes data as JSON
        print("Returning themes as JSON...")  # Step 11
        return JsonResponse(themes, safe=False)

    except subprocess.CalledProcessError as e:
        print(f"WP-CLI command failed: {e.stderr}")  # Error in wp-cli
        return JsonResponse({'error': f'WP-CLI command failed: {e.stderr}'}, status=500)
    except FileNotFoundError:
        print("WP-CLI not found or not installed.")  # Error if wp-cli is missing
        return JsonResponse({'error': 'WP-CLI not found or not installed.'}, status=500)
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")  # General exception
        return JsonResponse({'error': f'An unexpected error occurred: {str(e)}'}, status=500)




# def list_plugins(request):
#     try:
#         # Run the `wp plugin list` command with JSON output
#         result = subprocess.run(
#             ['wp', 'plugin', 'list', '--path=/home/rakesh/rakesh.com/public_html', '--allow-root', '--format=json'],
#             capture_output=True, text=True
#         )

#         # If there's an error running the command
#         if result.returncode != 0:
#             return JsonResponse({
#                 'error': 'Failed to retrieve plugins',
#                 'stderr': result.stderr  # Show error message from the command
#             })

#         # Load JSON output
#         plugins = json.loads(result.stdout)

#         return JsonResponse({'plugins': plugins})

#     except Exception as e:
#         return JsonResponse({'error': f'An unexpected error occurred: {str(e)}'})






# def wp_auto_login(request, website_id):
#     # Fetch website and credentials
#     website = get_object_or_404(Website, id=website_id)
#     wp_credentials = get_object_or_404(WordPressCredentials, website=website)

#     # WordPress login and admin URLs
#     wp_login_url = f"http://{website.website_name}/wp-login.php"
#     wp_dashboard_url = f"http://{website.website_name}/wp-admin/"

#     try:
#         # Start session to persist cookies
#         session = requests.Session()

#         # If the user has logged out or session is reset, directly set the WordPress cookies
#         cookies = {
#             f'wordpress_logged_in_{website.website_name}': f"{wp_credentials.wp_username}|{wp_credentials.wp_password}",
#             f'wordpress_sec_{website.website_name}': f"{wp_credentials.wp_username}|{wp_credentials.wp_password}"
#         }

#         # Manually set cookies for the session
#         session.cookies.update(cookies)

#         # Try accessing the WordPress dashboard directly
#         dashboard_response = session.get(wp_dashboard_url)

#         # Check if the dashboard was reached successfully
#         if dashboard_response.status_code == 302 and 'wp-admin' in dashboard_response.url:
#             logger.info("Successfully logged into WordPress dashboard.")
#             return redirect(wp_dashboard_url)
#         else:
#             logger.error("Failed to access WordPress dashboard, redirecting to login page.")
#             return HttpResponse(f"Failed to access dashboard. Response: {dashboard_response.text[:500]}", status=400)

#     except requests.ConnectionError as e:
#         logger.error(f"ConnectionError: {e}")
#         return HttpResponse(f"ConnectionError: {e}", status=500)
#     except Exception as e:
#         logger.error(f"An unexpected error occurred: {e}")
#         return HttpResponse(f"An unexpected error occurred: {e}", status=500)


# import requests
    # from bs4 import BeautifulSoup
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect
import logging

# Initialize logger
import logging
# import requests
# from bs4 import BeautifulSoup
from django.shortcuts import get_object_or_404, redirect
from django.http import HttpResponse

logger = logging.getLogger(__name__)

import logging
# import requests
# from bs4 import BeautifulSoup
from django.shortcuts import get_object_or_404, redirect
from django.http import HttpResponse

logger = logging.getLogger(__name__)
import logging
# import requests
# from bs4 import BeautifulSoup
from django.shortcuts import get_object_or_404, redirect
from django.http import HttpResponse

logger = logging.getLogger(__name__)
from django.views.decorators.cache import never_cache

from django.http import HttpResponse

# @never_cache
# def wp_auto_login(request, website_id):
#     website = get_object_or_404(Website, id=website_id)
#     wp_credentials = get_object_or_404(WordPressCredentials, website=website)

#     logger.info(f"Fetched WP credentials: Username: {wp_credentials.wp_username}, Password: {wp_credentials.wp_password}")

#     wp_login_url = f"http://{website.website_name}/wp-login.php"
#     wp_dashboard_url = f"http://{website.website_name}/wp-admin/"

#     try:
#         # Step 1: Get the login page to fetch hidden inputs and initial cookies
#         initial_response = requests.get(wp_login_url)
#         logger.info(f"Initial GET request status code: {initial_response.status_code}")

#         # Capture the cookies from the initial response
#         cookies = initial_response.cookies.get_dict()
#         logger.info(f"Initial cookies: {cookies}")

#         # Step 2: Parse the login page to get hidden fields (if any)
#         soup = BeautifulSoup(initial_response.text, 'html.parser')
#         hidden_inputs = soup.find_all("input", type="hidden")
#         logger.info(f"Found {len(hidden_inputs)} hidden inputs in the login form.")

#         # Step 3: Prepare login data
#         login_data = {
#             'log': wp_credentials.wp_username,
#             'pwd': wp_credentials.wp_password,
#             'wp-submit': 'Log In',
#             'redirect_to': wp_dashboard_url,
#             'testcookie': '1',
#         }

#         # Add hidden fields to login_data
#         for hidden_input in hidden_inputs:
#             name = hidden_input.get('name')
#             value = hidden_input.get('value')
#             if name:
#                 login_data[name] = value

#         logger.info(f"Login data prepared: {login_data}")

#         # Step 4: Send the login request, along with cookies
#         login_response = requests.post(wp_login_url, data=login_data, cookies=cookies)
#         logger.info(f"Login response status code: {login_response.status_code}")

#         # Capture cookies after login
#         session_cookies = login_response.cookies.get_dict()
#         logger.info(f"Session cookies after login attempt: {session_cookies}")

#         # Step 5: Check if login was successful by verifying the presence of 'wordpress_logged_in_*'
#         if "wordpress_logged_in" in session_cookies:
#             logger.info("Login successful, redirecting to dashboard.")

#             # Step 6: Access the dashboard using the session cookies
#             dashboard_response = requests.get(wp_dashboard_url, cookies=session_cookies)
#             logger.info(f"Dashboard response status code: {dashboard_response.status_code}")

#             if dashboard_response.status_code == 200:
#                 logger.info("Successfully accessed the WordPress admin dashboard.")
#                 return HttpResponseRedirect(wp_dashboard_url)
#             else:
#                 logger.error("Failed to access the dashboard. Check for issues.")
#                 return HttpResponse("Failed to access the dashboard.", status=400)
#         else:
#             logger.error("Login failed. Response did not indicate a successful login.")
#             return HttpResponse("Login failed. Check logs for details.", status=400)

#     except requests.ConnectionError as e:
#         logger.error(f"ConnectionError: {e}")
#         return HttpResponse(f"ConnectionError: {e}", status=500)
#     except Exception as e:
#         logger.error(f"An unexpected error occurred: {e}")
#         return HttpResponse(f"An unexpected error occurred: {e}", status=500)


@never_cache
def wp_auto_login(request, website_id):
    website = get_object_or_404(Website, id=website_id)
    wp_credentials = get_object_or_404(WordPressCredentials, website=website)

    logger.info(f": Username: {wp_credentials.wp_username}, Password: {wp_credentials.wp_password}")

    wp_login_url = f"http://{website.website_name}/wp-login.php"
    wp_dashboard_url = f"http://{website.website_name}/wp-admin/"
    
    # Create a new session for each login attempt
    session = requests.Session()

    try:
        # Step 1: Get the login page to fetch hidden inputs and cookies
        test_cookie_response = session.get(wp_login_url)
        logger.info(f"Test cookie response status code: {test_cookie_response.status_code}")

        # Step 2: Parse the login page to get hidden fields (if any)
        soup = BeautifulSoup(test_cookie_response.text, 'html.parser')
        hidden_inputs = soup.find_all("input", type="hidden")
        logger.info(f"Found {len(hidden_inputs)} hidden inputs in the login form.")

        # Step 3: Prepare login data
        login_data = {
            'log': wp_credentials.wp_username,
            'pwd': wp_credentials.wp_password,
            'wp-submit': 'Log In',
            'redirect_to': wp_dashboard_url,
            'testcookie': '1',
        }

        # Extract CSRF token and any other hidden fields from the login page
        csrf_token = None
        for hidden_input in hidden_inputs:
            name = hidden_input.get('name')
            value = hidden_input.get('value')
            if name:
                login_data[name] = value
                # Check if this input is the CSRF token
                if 'csrf' in name.lower():  # Assuming CSRF token has 'csrf' in its name
                    csrf_token = value

        logger.info(f"Login data prepared: {login_data}")

        # Step 4: Send the login request with session to retain cookies
        login_response = session.post(wp_login_url, data=login_data)
        logger.info(f"Login response status code: {login_response.status_code}")

        # Check session cookies after login
        logger.info(f"Session cookies after login attempt: {session.cookies.get_dict()}")

        if login_response.status_code == 200 and ("wp-admin" in login_response.url or "dashboard" in login_response.text):
            logger.info("Login Successfull, redirecting to the Dashboard.")
            
            # Redirect to the dashboard URL
            response = HttpResponseRedirect(wp_dashboard_url)

            # Set the WordPress username and password cookies
            response.set_cookie('wp_username', wp_credentials.wp_username, max_age=60*60*24*30)  # 30 days
            response.set_cookie('wp_password', wp_credentials.wp_password, max_age=60*60*24*30)  # 30 days
            
            # Optionally, you can also set the CSRF token cookie if needed
            if csrf_token:
                response.set_cookie('csrf_token', csrf_token, max_age=60*60*24*30)  # 30 days
            
            return response
        else:
            logger.error("Login failed. Response did not indicate a successful login.")
            return HttpResponse(f"Login failed. Response text: {login_response.text[:500]}", status=400)
            

    except requests.ConnectionError as e:
        logger.error(f"ConnectionError: {e}")
        return HttpResponse(f"ConnectionError: {e}", status=500)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        return HttpResponse(f"An unexpected error occurred: {e}", status=500)

# def wordpress(request,website_id):
#     website = get_object_or_404(Website, id=website_id)
#     context = {
#         'website': website
#     }
#     return render(request, 'user/website_info.html', context)


def wordpress_user(request, website_id):
    # Fetch the website instance using the website ID
    website = get_object_or_404(Website, id=website_id)
    # wp_credentials = get_object_or_404(WordPressCredentials, website=website)
    
    # Define the context dictionary with the variables you want to pass to the template
    context = {
        'website': website,
        # 'wp_username': wp_credentials.wp_username,  
        # 'wp_password': wp_credentials.wp_password,  # Fetching WordPress password
        # 'wp_database_name': wp_credentials.wp_database_name,  # Add the database name to context
        # 'wp_database_user': wp_credentials.wp_database_user, 
        # 'wp_database_pass':wp_credentials.wp_database_pass
    }
    
    # Render the template with the context
    return render(request, 'user/install_wordpress.html', context)




# def your_view(request, website_id):
#     website = get_object_or_404(Website, id=website_id)
#     wp_credentials = get_object_or_404(WordPressCredentials, website=website)

#     context = {
#         'website': website,
#         'wp_credentials': wp_credentials  # Pass credentials to the template
#     }
#     return render(request, 'user/install_wordpress.html', context)  # Make sure this template exists


# def your_view(request,website_id):
#     website = get_object_or_404(Website, id=website_id)
#     wp_credentials = get_object_or_404(WordPressCredentials,webiste=website)
#     context = {
#         'website': website,
#         'wp_username': wp_credentials.wp_username,  
#         'wp_password': wp_credentials.wp_password  # Fetching WordPress password
#     }
    
#     # Render the template with the context
#     return render(request, 'user/install_wordpress.html', context)

import random
import string


def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_wp_credentials(request, website_id):
    if request.method == 'GET':
        wp_username = 'wp_' + generate_random_string(8)
        wp_password = generate_random_string(12)
        wp_database_name = 'wp_' + generate_random_string(6)
        wp_database_user = 'db_' + generate_random_string(6)
        wp_database_pass = generate_random_string(10)

        return JsonResponse({
            'success': True,
            'wp_username': wp_username,
            'wp_password': wp_password,
            'wp_database_name': wp_database_name,
            'wp_database_user': wp_database_user,
            'wp_database_pass': wp_database_pass
        })
    else:
        return JsonResponse({'success': False, 'message': 'Invalid request method.'})

import os
import subprocess
from django.shortcuts import render

from .models import Website

import os
import subprocess
from django.shortcuts import render

from .models import Website
from django.db import connection

import os
import subprocess
import shutil

from django.db import connection

import os
import subprocess

from django.db import connection
import random
import string
import subprocess
import os
from django.http import JsonResponse
from django.shortcuts import render
from django.db import connection
from .models import Website, WordPressCredentials

def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


# from datetime import datetime
# import os
# import logging

# def create_log_file(ftp_username, website_name):
#     log_dir = f"/home/{ftp_username}/{website_name}/public_html/logs"
#     log_file = os.path.join(log_dir, "install_log.txt")
#     try:
#         os.makedirs(log_dir, exist_ok=True)
#         with open(log_file, "w") as f:
#             f.write(f"Installation Log for {website_name} - {datetime.now()}\n")
#     except PermissionError as e:
#         logging.error(f"PermissionError: {e}")
#         raise
#     return log_file


# # Function to append messages to the log file
# def log_message(log_file, message):
#     with open(log_file, "a") as file:
#         file.write(f"{datetime.now()} - {message}\n")

# # WordPress installation view
# def install_wordpress(request, website_id):
#     website = Website.objects.get(id=website_id)
#     public_html = f"/home/{website.ftp_username}/{website.website_name}/public_html"

#     wp_username = f"{website.ftp_username}_admin"
#     wp_password = generate_random_string()
#     wp_database_name = f"db_{generate_random_string(6)}"
#     wp_database_user = f"user_{generate_random_string(6)}"
#     wp_database_pass = generate_random_string()

#     log_file = create_log_file(website.ftp_username, website.website_name)

#     context = {
#         'website': website,
#         'wp_username': wp_username,
#         'wp_password': wp_password,
#         'wp_database_name': wp_database_name,
#         'wp_database_user': wp_database_user,
#         'wp_database_pass': wp_database_pass,
#     }

#     if request.method == 'POST':
#         wp_username = request.POST.get('wp_username')
#         wp_password = request.POST.get('wp_password')
#         wp_database_name = request.POST.get('wp_database_name')
#         wp_database_user = request.POST.get('wp_database_user')
#         wp_database_pass = request.POST.get('wp_database_pass')

#         with connection.cursor() as cursor:
#             cursor.execute("SELECT username, password FROM database_detials WHERE id = 1;")
#             result = cursor.fetchone()
#             if result:
#                 username, password = result
#             else:
#                 log_message(log_file, "Database credentials not found.")
#                 return JsonResponse({'status': 'error', 'message': "Database credentials not found."})

#         try:
#             log_message(log_file, "Starting WordPress installation.")
#             subprocess.run(['sudo', 'chmod', '-R', '777', public_html], check=True)
            
#             subprocess.run(['curl', '-o', '/tmp/wp-cli.phar', 'https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar'], check=True)
#             subprocess.run(['chmod', '+x', '/tmp/wp-cli.phar'], check=True)
#             subprocess.run(['sudo', 'mv', '/tmp/wp-cli.phar', '/usr/local/bin/wp'], check=True)

#             subprocess.run(['wget', 'https://wordpress.org/latest.tar.gz', '-P', public_html], check=True)
#             tar_file = os.path.join(public_html, 'latest.tar.gz')
#             if not os.path.isfile(tar_file):
#                 log_message(log_file, "WordPress tar file not found.")
#                 return JsonResponse({'status': 'error', 'message': 'WordPress tar file not found.'})

#             subprocess.run(['tar', '--strip-components=1', '-xzf', tar_file, '-C', public_html], check=True)
#             log_message(log_file, "WordPress files extracted.")

#             create_db_command = (
#                 f"CREATE DATABASE {wp_database_name}; "
#                 f"CREATE USER '{wp_database_user}'@'localhost' IDENTIFIED BY '{wp_database_pass}'; "
#                 f"GRANT ALL PRIVILEGES ON {wp_database_name}.* TO '{wp_database_user}'@'localhost'; "
#                 "FLUSH PRIVILEGES;"
#             )
#             mysql_command = ['mysql', '-u', username, f'-p{password}', '-e', create_db_command]
#             subprocess.run(mysql_command, check=True)
#             log_message(log_file, "Database created and user privileges granted.")

#             wp_config_sample = os.path.join(public_html, 'wp-config-sample.php')
#             wp_config = os.path.join(public_html, 'wp-config.php')
#             with open(wp_config_sample, 'r') as file:   
#                 config = file.read()
#             config = config.replace('database_name_here', wp_database_name)
#             config = config.replace('username_here', wp_database_user)
#             config = config.replace('password_here', wp_database_pass)
#             with open(wp_config, 'w') as file:
#                 file.write(config)
#             log_message(log_file, "wp-config.php file created.")

#             website_url = f"http://{website.website_name}"
#             wp_cli_command = [
#                 'sudo', '-u', website.ftp_username, '/usr/local/bin/wp', 'core', 'install',
#                 f'--url={website_url}',
#                 '--title=Your Site Title',
#                 f'--admin_user={wp_username}',
#                 f'--admin_password={wp_password}',
#                 '--admin_email=your-email@example.com',
#                 f'--path={public_html}'
#             ]
#             subprocess.run(wp_cli_command, check=True)
#             log_message(log_file, "WordPress installation completed.")

#             os.remove(tar_file)
#             subprocess.run(['sudo', 'chown', '-R', f'{website.ftp_username}:{website.ftp_username}', public_html], check=True)
#             subprocess.run(['sudo', 'chmod', '-R', '755', public_html], check=True)
#             subprocess.run(['sudo', 'systemctl', 'reload', 'apache2'], check=True)

#             credentials = WordPressCredentials(
#                 website=website,
#                 wp_username=wp_username,
#                 wp_password=wp_password,
#                 wp_database_name=wp_database_name,
#                 wp_database_user=wp_database_user,
#                 wp_database_pass=wp_database_pass
#             )
#             credentials.save()
#             log_message(log_file, "WordPress credentials saved to the database.")

#             return JsonResponse({'status': 'success', 'message': 'WordPress installation complete!'})

#         except subprocess.CalledProcessError as e:
#             log_message(log_file, f"Error during WordPress installation: {str(e)}")
#             return JsonResponse({'status': 'error', 'message': str(e)})

#     return render(request, 'user/install_wordpress.html', context)





def install_wordpress(request, website_id):
    website = Website.objects.get(id=website_id)
    public_html = f"/home/{website.ftp_username}/{website.website_name}/public_html"

    wp_username = f"{website.ftp_username}_admin"
    wp_password = generate_random_string()
    wp_database_name = f"db_{generate_random_string(6)}"
    wp_database_user = f"user_{generate_random_string(6)}"
    wp_database_pass = generate_random_string()

    context = {
        'website': website,
        'wp_username': wp_username,
        'wp_password': wp_password,
        'wp_database_name': wp_database_name,
        'wp_database_user': wp_database_user,
        'wp_database_pass': wp_database_pass,
    }

    if request.method == 'POST':
        wp_username = request.POST.get('wp_username')
        wp_password = request.POST.get('wp_password')
        wp_database_name = request.POST.get('wp_database_name')
        wp_database_user = request.POST.get('wp_database_user')
        wp_database_pass = request.POST.get('wp_database_pass')

        with connection.cursor() as cursor:
            cursor.execute("SELECT username, password FROM database_detials WHERE id = 1;")
            result = cursor.fetchone()
            if result:
                username, password = result
            else:
                return JsonResponse({'status': 'error', 'message': "Database credentials not found."})

        try:
            subprocess.run(['sudo', 'chmod', '-R', '777', public_html], check=True)

            subprocess.run(['curl', '-o', '/tmp/wp-cli.phar', 'https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar'], check=True)
            subprocess.run(['chmod', '+x', '/tmp/wp-cli.phar'], check=True)
            subprocess.run(['sudo', 'mv', '/tmp/wp-cli.phar', '/usr/local/bin/wp'], check=True)

            # Download WordPress
            subprocess.run(['wget', 'https://wordpress.org/latest.tar.gz', '-P', public_html], check=True)
            tar_file = os.path.join(public_html, 'latest.tar.gz')
            if not os.path.isfile(tar_file):
                return JsonResponse({'status': 'error', 'message': 'WordPress tar file not found.'})

            subprocess.run(['tar', '--strip-components=1', '-xzf', tar_file, '-C', public_html], check=True)

            # Create Database and User
            create_db_command = (
                f"CREATE DATABASE {wp_database_name}; "
                f"CREATE USER '{wp_database_user}'@'localhost' IDENTIFIED BY '{wp_database_pass}'; "
                f"GRANT ALL PRIVILEGES ON {wp_database_name}.* TO '{wp_database_user}'@'localhost'; "
                "FLUSH PRIVILEGES;"
            )
            mysql_command = ['mysql', '-u', username, f'-p{password}', '-e', create_db_command]
            subprocess.run(mysql_command, check=True)

            # Configure wp-config.php
            wp_config_sample = os.path.join(public_html, 'wp-config-sample.php')
            wp_config = os.path.join(public_html, 'wp-config.php')
            with open(wp_config_sample, 'r') as file:   
                config = file.read()
            config = config.replace('database_name_here', wp_database_name)
            config = config.replace('username_here', wp_database_user)
            config = config.replace('password_here', wp_database_pass)
            with open(wp_config, 'w') as file:
                file.write(config)

            website_url = f"http://{website.website_name}"
            wp_cli_command = [
                'sudo', '-u', website.ftp_username, '/usr/local/bin/wp', 'core', 'install',
                f'--url={website_url}',
                '--title=Your Site Title',
                f'--admin_user={wp_username}',
                f'--admin_password={wp_password}',
                '--admin_email=your-email@example.com',
                f'--path={public_html}'
            ]
            subprocess.run(wp_cli_command, check=True)

            os.remove(tar_file)
            subprocess.run(['sudo', 'chown', '-R', f'{website.ftp_username}:{website.ftp_username}', public_html], check=True)
            subprocess.run(['sudo', 'chmod', '-R', '777', public_html], check=True)
            subprocess.run(['sudo', 'systemctl', 'reload', 'apache2'], check=True)

            credentials = WordPressCredentials(
                website=website,
                wp_username=wp_username,
                wp_password=wp_password,
                wp_database_name=wp_database_name,
                wp_database_user=wp_database_user,
                wp_database_pass=wp_database_pass
            )
            credentials.save()

            return JsonResponse({'status': 'success', 'message': 'WordPress installation complete!'})

        except subprocess.CalledProcessError as e:
            return JsonResponse({'status': 'error', 'message': str(e)})

    return render(request, 'user/install_wordpress.html', context)


from django.shortcuts import redirect
import subprocess

import os
from django.shortcuts import redirect
from django.db import connection
import subprocess

def uninstall_wordpress(request, website_id):
    try:
        website = Website.objects.get(id=website_id)
        public_html = f"/home/{website.ftp_username}/{website.website_name}/public_html"

        # Fetch WordPress credentials associated with this website
        credentials = WordPressCredentials.objects.filter(website=website).first()
        if not credentials:
            return redirect('install_wordpress', website_id=website_id)  # Pass website_id

        wp_database_name = credentials.wp_database_name
        wp_database_user = credentials.wp_database_user

        if request.method == 'POST':
            
            wordpress_items = [
                'index.php', 'license.txt', 'readme.html',
                'wp-activate.php', 'wp-blog-header.php', 'wp-comments-post.php',
                'wp-config.php', 'wp-config-sample.php', 'wp-cron.php',
                'wp-links-opml.php', 'wp-load.php', 'wp-login.php',
                'wp-mail.php', 'wp-settings.php', 'wp-signup.php',
                'wp-trackback.php', 'xmlrpc.php',
                'wp-admin', 'wp-content', 'wp-includes',
                'latest.tar.gz'  # Include latest.tar.gz for removal
            ]

            
            for item in wordpress_items:
                item_path = os.path.join(public_html, item)
                if os.path.exists(item_path):
                    if os.path.isdir(item_path):
                        subprocess.run(['sudo', 'rm', '-rf', item_path], check=True)  # Remove directories
                    else:
                        subprocess.run(['sudo', 'rm', '-f', item_path], check=True)  # Remove files

            
            with connection.cursor() as cursor:
                cursor.execute("SELECT username, password FROM database_detials WHERE id = 1;")
                result = cursor.fetchone()
                if result:
                    db_root_user, db_root_pass = result
                else:
                    return redirect('install_wordpress', website_id=website_id)  

           
            delete_db_command = (
                f"DROP DATABASE IF EXISTS {wp_database_name}; "
                f"DROP USER IF EXISTS '{wp_database_user}'@'localhost'; "
            )
            mysql_command = ['mysql', '-u', db_root_user, f'-p{db_root_pass}', '-e', delete_db_command]
            subprocess.run(mysql_command, check=True)

            # Remove WordPress credentials from the database
            credentials.delete()

            # Redirect to the install_wordpress.html page
            return redirect('install_wordpress', website_id=website_id)  # Pass website_id

    except Website.DoesNotExist:
        return redirect('install_wordpress', website_id=website_id)  # Redirect if website not found
    except subprocess.CalledProcessError as e:
        return redirect('install_wordpress', website_id=website_id)  # Redirect on subprocess error
    except Exception as e:
        return redirect('install_wordpress', website_id=website_id)  # Redirect on unexpected error

    return redirect('install_wordpress', website_id=website_id)  # Default redirect for invalid request method




# def uninstall_wordpress(request, website_id):
#     try:
#         website = Website.objects.get(id=website_id)
#         public_html = f"/home/{website.ftp_username}/{website.website_name}/public_html"

#         # Fetch WordPress credentials associated with this website
#         credentials = WordPressCredentials.objects.filter(website=website).first()
#         if not credentials:
#             return redirect('install_wordpress', website_id=website_id)  # Pass website_id

#         wp_database_name = credentials.wp_database_name
#         wp_database_user = credentials.wp_database_user

#         if request.method == 'POST':
#             # Remove WordPress files
#             subprocess.run(['sudo', 'rm', '-rf', public_html], check=True)

#             # Retrieve MySQL root credentials
#             with connection.cursor() as cursor:
#                 cursor.execute("SELECT username, password FROM database_detials WHERE id = 1;")
#                 result = cursor.fetchone()
#                 if result:
#                     db_root_user, db_root_pass = result
#                 else:
#                     return redirect('install_wordpress', website_id=website_id)  # Redirect on failure

#             # Delete Database and User
#             delete_db_command = (
#                 f"DROP DATABASE IF EXISTS {wp_database_name}; "
#                 f"DROP USER IF EXISTS '{wp_database_user}'@'localhost'; "
#             )
#             mysql_command = ['mysql', '-u', db_root_user, f'-p{db_root_pass}', '-e', delete_db_command]
#             subprocess.run(mysql_command, check=True)

#             # Remove WordPress credentials from the database
#             credentials.delete()

#             # Redirect to the install_wordpress.html page
#             return redirect('install_wordpress', website_id=website_id)  # Pass website_id

#     except Website.DoesNotExist:
#         return redirect('install_wordpress', website_id=website_id)  # Redirect if website not found
#     except subprocess.CalledProcessError as e:
#         return redirect('install_wordpress', website_id=website_id)  # Redirect on subprocess error
#     except Exception as e:
#         return redirect('install_wordpress', website_id=website_id)  # Redirect on unexpected error

#     return redirect('install_wordpress', website_id=website_id)  # Default redirect for invalid request method



# from django.http import JsonResponse
# import subprocess
# import os

# def uninstall_wordpress(request, website_id):
#     website = Website.objects.get(id=website_id)
#     public_html = f"/home/{website.ftp_username}/{website.website_name}/public_html"

#     if request.method == 'POST':
#         try:
#             # Delete WordPress files
#             subprocess.run(['sudo', 'rm', '-rf', public_html], check=True)

#             # Delete Database and User
#             with connection.cursor() as cursor:
#                 cursor.execute("SELECT username, password FROM database_detials WHERE id = 1;")
#                 result = cursor.fetchone()
#                 if result:
#                     username, password = result
#                 else:
#                     return JsonResponse({'status': 'error', 'message': "Database credentials not found."})

#             delete_db_command = (
#                 f"DROP DATABASE IF EXISTS {website.wp_database_name}; "
#                 f"DROP USER IF EXISTS '{website.wp_database_user}'@'localhost'; "
#             )
#             mysql_command = ['mysql', '-u', username, f'-p{password}', '-e', delete_db_command]
#             subprocess.run(mysql_command, check=True)

#             # Remove saved credentials if any
#             WordPressCredentials.objects.filter(website=website).delete()

#             return JsonResponse({'status': 'success', 'message': 'WordPress uninstalled successfully!'})

#         except subprocess.CalledProcessError as e:
#             return JsonResponse({'status': 'error', 'message': str(e)})

#     return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})




import os
import subprocess
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Website 

# def install_wordpress(request, website_id):
#     website = Website.objects.get(id=website_id)
#     if request.method == 'POST':
#         wp_username = request.POST.get('wp_username')
#         wp_password = request.POST.get('wp_password')
#         wp_database_name = request.POST.get('wp_database_name')
#         wp_database_user = request.POST.get('wp_database_user')
#         wp_database_pass = request.POST.get('wp_database_pass')
#         user_home = f"/home/{request.user.username}"
#         public_html = f"/home/{website.ftp_username}/{website.website_name}/public_html"

#         # Ensure the public_html directory exists
#         if not os.path.exists(public_html):
#             messages.error(request, f"Directory {public_html} does not exist.")
#             return redirect('install_wordpress', website_id)

#         try:
#             # Detect PHP version
#             php_version = website.php_version  # Use the PHP version stored in the database
#             # Install PHP MySQL extension
#             install_php_mysqli(php_version)
#             # Install WordPress
#             install_wordpress_for_domain(domain, wp_username, wp_password, wp_database_name, wp_database_user, wp_database_pass, public_html)
            
#             messages.success(request, f"WordPress installed successfully for {domain}!")
#             return redirect('install_wordpress', website_id)
#         except Exception as e:
#             messages.error(request, f"Failed to install WordPress: {str(e)}")
#             return redirect('install_wordpress', website_id)
#     return render(request, 'user/install_wordpress.html')

def install_php_mysqli(php_version):
    # Use only the major version (e.g., 7.4 instead of 7.4.33)
    major_php_version = php_version.split('.')[0:2]
    major_php_version = '.'.join(major_php_version)  # e.g., "7.4"

    # Install the PHP MySQL extension for the detected version
    if os.path.exists('/etc/debian_version'):
        subprocess.run(['sudo', 'apt', 'update'], check=True)
        subprocess.run(['sudo', 'apt', 'install', f'php{major_php_version}-mysql', '-y'], check=True)
    elif os.path.exists('/etc/redhat-release'):
        subprocess.run(['sudo', 'yum', 'install', 'php-mysql', '-y'], check=True)
    else:
        raise Exception("Unsupported Linux distribution.")

# def install_wordpress_for_domain(domain, wp_username, wp_password, wp_database_name, wp_database_user, wp_database_pass, public_html):
#     # Download WordPress
#     download_command = subprocess.run(['wget', '-q', '-O', '/tmp/latest.zip', 'http://wordpress.org/latest.zip'], check=False)
#     if download_command.returncode != 0:
#         raise Exception("Failed to download WordPress.")

#     # Unzip the downloaded file
#     unzip_command = subprocess.run(['unzip', '-q', '/tmp/latest.zip', '-d', '/tmp/'], check=False)
#     if unzip_command.returncode != 0:
#         raise Exception("Failed to unzip WordPress.")

#     # Move files to public_html
#     move_command = subprocess.run(['mv', '/tmp/wordpress/*', public_html], check=False)
#     if move_command.returncode != 0:
#         raise Exception("Failed to move WordPress files to public_html.")

#     # Set appropriate permissions
#     subprocess.run(['chown', '-R', 'www-data:www-data', public_html], check=True)
#     subprocess.run(['chmod', '-R', '755', public_html], check=True)

#     # Configure MySQL database
#     mysql_commands = f"""
#     CREATE DATABASE {wp_database_name};
#     CREATE USER '{wp_database_user}'@'localhost' IDENTIFIED BY '{wp_database_pass}';
#     GRANT ALL PRIVILEGES ON {wp_database_name}.* TO '{wp_database_user}'@'localhost';
#     FLUSH PRIVILEGES;
#     """
#     subprocess.run(['mysql', '-u', 'root', '-p'], input=mysql_commands.encode('utf-8'), check=True)

#     # Configure WordPress
#     wp_config = os.path.join(public_html, "wp-config.php")
#     subprocess.run(['cp', os.path.join(public_html, 'wp-config-sample.php'), wp_config], check=True)
#     subprocess.run(['sed', '-i', f"s/database_name_here/{wp_database_name}/", wp_config], check=True)
#     subprocess.run(['sed', '-i', f"s/username_here/{wp_database_user}/", wp_config], check=True)
#     subprocess.run(['sed', '-i', f"s/password_here/{wp_database_pass}/", wp_config], check=True)

#     # Install WordPress using WP-CLI
#     install_wp_cli()
#     subprocess.run(['wp', 'core', 'install', '--url', domain, '--title', domain,
#                     '--admin_user', wp_username, '--admin_password', wp_password,
#                     '--admin_email', 'admin@example.com'], cwd=public_html, check=True)

# def install_wp_cli():
#     # Check if WP-CLI is already installed
#     try:
#         subprocess.run(['wp', '--info'], check=True)
#     except subprocess.CalledProcessError:
#         # Download and install WP-CLI
#         subprocess.run(['curl', '-O', 'https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar'], check=True)
#         subprocess.run(['chmod', '+x', 'wp-cli.phar'], check=True)
#         subprocess.run(['mv', 'wp-cli.phar', '/usr/local/bin/wp'], check=True)

def additional_ftp(request, website_id):
    website = get_object_or_404(Website, id=website_id)
    print(f"Website ID: {website_id}, Website: {website}")

    # Define the base directory for the website's FTP user, including the domain name
    base_dir = os.path.join('/home', website.ftp_username, website.website_name)
    print(f"Base directory: {base_dir}")

    # Initialize the directories list
    directories = []

    def list_directories(path, parent=None):
        directories_list = []
        try:
            for entry in os.scandir(path):
                if entry.is_dir():
                    dir_info = {'name': entry.name, 'subdirectories': []}
                    # Recursively find subdirectories
                    subdirs = list_directories(entry.path, parent=dir_info)
                    if subdirs:
                        dir_info['subdirectories'] = subdirs
                    directories_list.append(dir_info)
        except PermissionError as e:
            print(f"PermissionError while scanning directory {path}: {e}")
        return directories_list

    directories = list_directories(base_dir)
    print(f"Directories found: {directories}")

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        specific_directory = request.POST.get('specific_directory')

        print(f"POST data - Username: {username}, Password: {password}, Specific Directory: {specific_directory}")

        if username and password and specific_directory:
            try:
                specific_path = os.path.join(base_dir, specific_directory)
                print(f"Specific path: {specific_path}")
                
                # Ensure the directory exists
                if not os.path.isdir(specific_path):
                    print(f"Creating directory: {specific_path}")
                    os.makedirs(specific_path)

                # Configure vsftpd to restrict the user to the selected directory
                vsftpd_conf = f"""
                local_root={os.path.join(base_dir, specific_directory)}
                write_enable=YES
                local_umask=022
                file_open_mode=0755
                chroot_local_user=YES
                allow_writeable_chroot=YES
                """
                print(f"vsftpd configuration for {username}:\n{vsftpd_conf}")

                # Write the vsftpd configuration for the new user
                conf_path = f'/etc/vsftpd/user_conf/{username}'
                with open(conf_path, 'w') as conf_file:
                    conf_file.write(vsftpd_conf)

                # Change the ownership of the configuration file to the vsftpd user
                subprocess.run(['sudo', 'chown', 'root:root', conf_path], check=True)
                subprocess.run(['sudo', 'chmod', '644', conf_path], check=True)
                print(f"Configuration file permissions set for {conf_path}")

                # Add the user to the system with no shell access
                subprocess.run(['sudo', 'useradd', '-m', '-d', f'/home/{username}', '-s', '/bin/bash', username], check=True)
                subprocess.run(['sudo', 'chpasswd'], input=f'{username}:{password}', text=True, check=True)
                print(f"User {username} added successfully.")

                # Change the ownership of the user's home directory to the new user
                user_home_dir = f'/home/{username}'
                subprocess.run(['sudo', 'chown', '-R', f'{username}:{username}', user_home_dir], check=True)

                subprocess.run(['sudo', 'chmod', '775', specific_path], check=True)
                subprocess.run(['sudo', 'chown', '-R', f'{username}:{website.ftp_username}', specific_path], check=True)

                messages.success(request, 'FTP user created successfully!')
                return redirect('ftp_users', website.id)

            except Exception as e:
                print(f"Error creating FTP user: {e}")
                messages.error(request, f'Error creating FTP user: {e}')
        else:
            messages.error(request, 'All fields are required.')

    context = {
        'website': website,
        'directories': directories,
    }
    return render(request, 'user/additional_ftp.html', context)


# Example function call
# additional_ftp(ftp_username='exampleuser', ftp_password='examplepass', specific_directory='/var/www/example', website_id=77)


def file_manager(request, website_id):
    website = get_object_or_404(Website, id=website_id)
    
    # Get the current directory from query parameters, default to root
    current_dir = request.GET.get('dir', '')
    
    # Construct the full path based on the current directory
    base_directory = f"/home/{website.ftp_username}/{website.website_name}"

    file_directory = os.path.join(base_directory, current_dir)

    # Ensure the user isn't attempting to access directories outside their allowed path
    if not file_directory.startswith(base_directory):
        raise Http404("Access denied")

    # Debug statement to print the directory being accessed
    print(f"Attempting to list directory: {file_directory}")
    
    # Get the list of files and directories with details
    try:
        files_and_dirs = os.listdir(file_directory)
        print(f"Found files and directories: {files_and_dirs}")  # Debug statement to print the contents
    except Exception as e:
        print(f"Error accessing directory: {e}")  # Debug statement to print any error that occurs
        files_and_dirs = []

    # Gather details for each file and directory
    entries = []
    for entry in files_and_dirs:
        entry_path = os.path.join(file_directory, entry)
        stat_info = os.stat(entry_path)
        entry_info = {
            'name': entry,
            'permissions': stat.filemode(stat_info.st_mode),  # Convert to human-readable format
            'size': stat_info.st_size,
            'owner': pwd.getpwuid(stat_info.st_uid).pw_name,
            'group': grp.getgrgid(stat_info.st_gid).gr_name,
            'modified_time': datetime.fromtimestamp(stat_info.st_mtime),
            'is_dir': os.path.isdir(entry_path),
        }
        entries.append(entry_info)

    # Generate the parent directory link
    parent_dir = os.path.dirname(current_dir) if current_dir else None

    context = {
        'website': website,
        'entries': entries,
        'current_dir': current_dir,
        'parent_dir': parent_dir,
    }
    return render(request, 'user/file_manager.html', context)

# import os
# from django.shortcuts import render, get_object_or_404
# from django.http import Http404

# def file_manager(request, website_id):
#     website = get_object_or_404(Website, id=website_id)
    
#     # Get the current directory from query parameters, default to root
#     current_dir = request.GET.get('dir', '')
    
#     # Construct the full path based on the current directory
#     base_directory = f"/home/{website.ftp_username}/{website.website_name}"
#     file_directory = os.path.join(base_directory, current_dir)

#     # Ensure the user isn't attempting to access directories outside their allowed path
#     if not file_directory.startswith(base_directory):
#         raise Http404("Access denied")

#     # Debug statement to print the directory being accessed
#     print(f"Attempting to list directory: {file_directory}")
    
#     # Get the list of files and directories
#     try:
#         files_and_dirs = os.listdir(file_directory)
#         print(f"Found files and directories: {files_and_dirs}")  # Debug statement to print the contents
#     except Exception as e:
#         print(f"Error accessing directory: {e}")  # Debug statement to print any error that occurs
#         files_and_dirs = []

#     # Separate files and directories for better display
#     files = [f for f in files_and_dirs if os.path.isfile(os.path.join(file_directory, f))]
#     directories = [d for d in files_and_dirs if os.path.isdir(os.path.join(file_directory, d))]

#     # Generate the parent directory link
#     parent_dir = os.path.dirname(current_dir) if current_dir else None

#     context = {
#         'website': website,
#         'files': files,
#         'directories': directories,
#         'current_dir': current_dir,
#         'parent_dir': parent_dir,
#     }
#     return render(request, 'user/file_manager.html', context)


# import os
# from django.shortcuts import render, get_object_or_404

# def file_manager(request, website_id):
#     website = get_object_or_404(Website, id=website_id)
    
#     # Define the directory path based on the website's FTP username
#     file_directory = f"/home/{website.ftp_username}/{website.website_name}"
#     print(f"Directory Path: {file_directory}")
    
#     # Get the list of files and directories
#     try:
#         files_and_dirs = os.listdir(file_directory)
#         print(f"Found files and directories: {files_and_dirs}")  # Debug statement to print the contents
#     except Exception as e:
#         print(f"Error accessing directory: {e}")  # Debug statement to print any error that occurs
#         files_and_dirs = []

#     # Separate files and directories for better display
#     files = [f for f in files_and_dirs if os.path.isfile(os.path.join(file_directory, f))]
#     directories = [d for d in files_and_dirs if os.path.isdir(os.path.join(file_directory, d))]

#     context = {
#         'website': website,
#         'files': files,
#         'directories': directories,
#     }
#     return render(request, 'user/file_manager.html', context)




from django.shortcuts import render, get_object_or_404
from .models import Subdomain, Website

def website_info(request, id):
    subdomain = Subdomain.objects.filter(id=id).first()
    
    if subdomain:
        # If it's a subdomain, get the related website
        context = {
            'subdomain': subdomain,
            'website': subdomain.website,
            'is_subdomain': True
        }
    else:
        # If it's a website
        website = get_object_or_404(Website, id=id)
        context = {
            'website': website,
            'is_subdomain': False
        }
    
    return render(request, 'user/website_info.html', context)

def subdomain_info(request, id):
    subdomain = get_object_or_404(Subdomain, id=id)
    context = {
        'subdomain': subdomain,
        'website': subdomain.website,
        'is_subdomain': True
    }
    return render(request, 'user/subdomain_info.html', context)

# def website_info(request, id):
#     website = get_object_or_404(Website, id=id)
#     logger.info(f"Website: {website}")  # Check if this appears in your logs
#     return render(request, 'user/website_info.html', {'website': website})

# views.py
from django.shortcuts import render, get_object_or_404
from popo.models import Customer, Website


def customer_detail(request, customer_id):
    customer = get_object_or_404(Customer, id=customer_id)
    websites = Website.objects.filter(customer=customer)
    return render(request, 'user/customer_detail.html', {
        'customer': customer,
        'websites': websites
    })


@login_required
def list_customers(request):
    customers = Customer.objects.all()
    # for customer in customers:
    #     print(f"Customer ID: {customer.id}, Full Name: {customer.full_name}")
    return render(request, 'user/list_customers.html', {'customers': customers})

    
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib import messages
from .models import Website, Subdomain


def ftp_users(request, website_id):
    website = get_object_or_404(Website, id=website_id)
    if request.method == 'POST':
        ftp_username = request.POST.get('ftp_username')
        ftp_password = request.POST.get('ftp_password')
        if ftp_username and ftp_password:
            website.ftp_username = ftp_username
            website.ftp_password = ftp_password
            website.save()
            messages.success(request, 'FTP details updated successfully.')
            return redirect('ftp_users', website_id=website.id)
        else:
            messages.error(request, 'Please fill in both fields.')
    return render(request, 'user/ftp_users.html', {'website': website})
    

from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from popo.models import Customer

def HomePage(request):
    if request.user.is_authenticated:
        # Admin user is logged in
        user_id = request.user.id
        return render(request, 'user/home.html', {'user_id': user_id})

    return redirect('login')

from django.shortcuts import render, redirect
from popo.models import Customer

def userhome(request):
    customer_id = request.session.get('customer_id')
    if customer_id:
        try:
            # Fetch the customer using the ID from the session
            customer = Customer.objects.get(id=customer_id)
            return render(request, 'user/userhome.html', {'customer': customer})
        except Customer.DoesNotExist:
            # If the customer does not exist, clear the session and redirect to login
            request.session.flush()
            return redirect('login')
    else:
        # No customer ID in session, redirect to login
        return redirect('login')


# @login_required
# def list_websites(request):
#     user_id = request.user.id
#     websites = Website.objects.all()
#     subdomains = Subdomain.objects.all()
#     return render(request, 'user/list_websites.html', {'websites': websites,'user_id': user_id , 'subdomains': subdomains })

@login_required
def list_websites(request):
    user_id = request.user.id
    websites = Website.objects.all()

    website_data = []
    for website in websites:
        subdomains = Subdomain.objects.filter(website=website)
        subdomain_names = [subdomain.subdomain_name for subdomain in subdomains]  # Use subdomain_name
        website_data.append({
            'website_id': website.id,
            'website_name': website.website_name,
            'subdomains': subdomains
        })

    return render(request, 'user/list_websites.html', {'website_data': website_data, 'user_id': user_id})


import subprocess
import os
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from django.urls import reverse


def update_ftp_user(request, website_id):
    if request.method == 'POST':
        # Retrieve the website instance
        website = get_object_or_404(Website, id=website_id)

        # Get the current, new, and confirm FTP details from the form
        current_ftp_password = request.POST.get('current_ftp_password')
        new_ftp_password = request.POST.get('new_ftp_password')
        confirm_ftp_password = request.POST.get('confirm_ftp_password')
        new_ftp_username = request.POST.get('ftp_username')
        old_ftp_username = website.ftp_username

        if website.ftp_password != current_ftp_password:
            messages.error(request, "Current FTP password is incorrect.")
            return redirect(reverse('ftp_users', args=[website_id]))

        if new_ftp_password != confirm_ftp_password:
            messages.error(request, "New FTP passwords do not match.")
            return redirect(reverse('ftp_users', args=[website_id]))

        vsftpd_user_conf_dir = "/etc/vsftpd/user_conf/"
        old_vsftpd_user_conf = f"{vsftpd_user_conf_dir}/{old_ftp_username}"
        new_vsftpd_user_conf = f"{vsftpd_user_conf_dir}/{new_ftp_username}"

        apache_conf = f"/etc/apache2/sites-available/{website.website_name}.conf"
        apache_config_content = f"""
<VirtualHost *:80>
    ServerAdmin webmaster@{website.website_name}
    ServerName {website.website_name}
    DocumentRoot /home/{new_ftp_username}/{website.website_name}/public_html/
    <Directory /home/{new_ftp_username}/{website.website_name}/public_html/>
        AllowOverride all
        Require all granted
        Options FollowSymlinks
        # DirectoryIndex home.html
        Allow from all
    </Directory>
    ErrorLog /home/{new_ftp_username}/{website.website_name}/logs/error.log
    CustomLog /home/{new_ftp_username}/{website.website_name}/logs/access.log combined
</VirtualHost>
        """

        try:
            # If the FTP username has changed, handle user and configuration updates
            if old_ftp_username != new_ftp_username:
                # Rename the user
                subprocess.run(['sudo', 'usermod', '-l', new_ftp_username, old_ftp_username], check=True)

                # Rename the home directory
                old_home_dir = f'/home/{old_ftp_username}'
                new_home_dir = f'/home/{new_ftp_username}'
                if os.path.exists(old_home_dir):
                    subprocess.run(['sudo', 'usermod', '-d', new_home_dir, '-m', new_ftp_username], check=True)
                else:
                    subprocess.run(['sudo', 'mkdir', '-p', new_home_dir], check=True)
                    subprocess.run(['sudo', 'usermod', '-d', new_home_dir, '-m', new_ftp_username], check=True)

                # Ensure the group exists or create it
                try:
                    subprocess.run(['sudo', 'groupadd', new_ftp_username], check=True)
                except subprocess.CalledProcessError:
                    # Ignore the error if the group already exists
                    pass

                # Set correct ownership and permissions
                subprocess.run(['sudo', 'chown', '-R', f'{new_ftp_username}:{new_ftp_username}', new_home_dir], check=True)
                subprocess.run(['sudo', 'chmod', '-R', '755', new_home_dir], check=True)

                # Delete the old vsftpd configuration
                if os.path.exists(old_vsftpd_user_conf):
                    subprocess.run(['sudo', 'rm', '-f', old_vsftpd_user_conf], check=True)
                    print(f"Deleted old vsftpd config: {old_vsftpd_user_conf}")

                # Update Apache virtual host configuration
                subprocess.run(f'sudo sh -c "echo \'{apache_config_content}\' > {apache_conf}"', shell=True, check=True)
                print(f"Apache virtual host configuration updated: {apache_conf}")

                # Update website's FTP username
                website.ftp_username = new_ftp_username

            # Update the password
            subprocess.run(['sudo', 'chpasswd'], input=f'{new_ftp_username}:{new_ftp_password}'.encode(), check=True)
            website.ftp_password = new_ftp_password

            # Ensure the vsftpd user configuration directory exists
            subprocess.run(['sudo', 'mkdir', '-p', vsftpd_user_conf_dir], check=True)

            # Create the new vsftpd configuration for the user
            vsftpd_config_content = f"""
local_root=/home/{new_ftp_username}
write_enable=YES
local_umask=022
file_open_mode=0755
            """
            subprocess.run(f'sudo sh -c "echo \'{vsftpd_config_content}\' > {new_vsftpd_user_conf}"', shell=True, check=True)

            # Restart vsftpd to apply changes
            subprocess.run(['sudo', 'systemctl', 'restart', 'vsftpd'], check=True)

            # Save the changes to the website instance
            website.save()

            # Provide a success message
            messages.success(request, f"FTP details for {website.website_name} updated successfully.")

        except subprocess.CalledProcessError as e:
            error_message = e.stderr.decode() if e.stderr else str(e)
            messages.error(request, f"Error updating FTP user: {error_message}")
            print(f"Debug Info: Command '{e.cmd}' returned non-zero exit status {e.returncode}.")

        # Redirect to the FTP details page
        return redirect(reverse('ftp_users', args=[website_id]))

    # If the request method is not POST, redirect to the website details page
    return redirect(reverse('website_info', args=[website_id]))



# import subprocess
# import os
# from django.shortcuts import get_object_or_404, redirect
# from django.contrib import messages
# from django.urls import reverse


# def update_ftp_user(request, website_id):
#     if request.method == 'POST':
#         # Retrieve the website instance
#         website = get_object_or_404(Website, id=website_id)

#         # Get the new FTP details from the form
#         new_ftp_username = request.POST.get('ftp_username')
#         new_ftp_password = request.POST.get('ftp_password')
#         old_ftp_username = website.ftp_username

#         try:
#             vsftpd_user_conf_dir = "/etc/vsftpd/user_conf/"
#             old_vsftpd_user_conf = f"{vsftpd_user_conf_dir}/{old_ftp_username}"
#             new_vsftpd_user_conf = f"{vsftpd_user_conf_dir}/{new_ftp_username}"

#             # If the FTP username has changed, rename the existing user and remove the old vsftpd config
#             if old_ftp_username != new_ftp_username:
#                 # Rename the user
#                 subprocess.run(['sudo', 'usermod', '-l', new_ftp_username, old_ftp_username], check=True)

#                 # Rename the home directory
#                 old_home_dir = f'/home/{old_ftp_username}'
#                 new_home_dir = f'/home/{new_ftp_username}'
#                 if os.path.exists(old_home_dir):
#                     subprocess.run(['sudo', 'usermod', '-d', new_home_dir, '-m', new_ftp_username], check=True)
#                 else:
#                     subprocess.run(['sudo', 'mkdir', '-p', new_home_dir], check=True)
#                     subprocess.run(['sudo', 'usermod', '-d', new_home_dir, '-m', new_ftp_username], check=True)

#                 # Ensure the group exists or create it
#                 try:
#                     subprocess.run(['sudo', 'groupadd', new_ftp_username], check=True)
#                 except subprocess.CalledProcessError:
#                     # Ignore the error if the group already exists
#                     pass

#                 # Set correct ownership and permissions
#                 subprocess.run(['sudo', 'chown', '-R', f'{new_ftp_username}:{new_ftp_username}', new_home_dir], check=True)
#                 subprocess.run(['sudo', 'chmod', '-R', '755', new_home_dir], check=True)

#                 # Delete the old vsftpd configuration
#                 if os.path.exists(old_vsftpd_user_conf):
#                     subprocess.run(['sudo', 'rm', '-f', old_vsftpd_user_conf], check=True)
#                     print(f"Deleted old vsftpd config: {old_vsftpd_user_conf}")

#                 website.ftp_username = new_ftp_username

#             # Update the password
#             subprocess.run(['sudo', 'chpasswd'], input=f'{new_ftp_username}:{new_ftp_password}'.encode(), check=True)
#             website.ftp_password = new_ftp_password

#             # Ensure the vsftpd user configuration directory exists
#             subprocess.run(['sudo', 'mkdir', '-p', vsftpd_user_conf_dir], check=True)

#             # Create the new vsftpd configuration for the user
#             vsftpd_config_content = f"""
# local_root=/home/{new_ftp_username}
# write_enable=YES
# local_umask=022
# file_open_mode=0755
#             """
#             subprocess.run(f'sudo sh -c "echo \'{vsftpd_config_content}\' > {new_vsftpd_user_conf}"', shell=True, check=True)

#             # Restart vsftpd to apply changes
#             subprocess.run(['sudo', 'systemctl', 'restart', 'vsftpd'], check=True)

#             # Save the changes to the website instance
#             website.save()

#             # Provide a success message
#             messages.success(request, f"FTP details for {website.website_name} updated successfully.")

#         except subprocess.CalledProcessError as e:
#             error_message = e.stderr.decode() if e.stderr else str(e)
#             messages.error(request, f"Error updating FTP user: {error_message}")
#             print(f"Debug Info: Command '{e.cmd}' returned non-zero exit status {e.returncode}.")

#         # Redirect to the FTP details page
#         return redirect(reverse('ftp_users', args=[website_id]))

#     # If the request method is not POST, redirect to the website details page
#     return redirect(reverse('website_info', args=[website_id]))



@csrf_protect
@login_required
def update_website(request, website_id):
    user_id = request.user.id
    website = get_object_or_404(Website, id=website_id)

    if request.method == 'POST':
        new_website_name = request.POST.get('website_name')
        new_ftp_username = request.POST.get('ftp_username')
        new_ftp_password = request.POST.get('ftp_password')
        new_php_version = request.POST.get('php_version')

        if not (new_website_name and new_ftp_username and new_ftp_password and new_php_version):
            messages.error(request, 'Please fill out all required fields')
            return redirect('update_website', website_id=website.id)

        if not (new_website_name.endswith('.com') or new_website_name.endswith('.in')):
            messages.error(request, 'Website name must end with .com or .in')
            return redirect('update_website', website_id=website.id)

        try:
            old_ftp_username = website.ftp_username
            old_website_name = website.website_name

            if new_ftp_username != old_ftp_username:
                print(f"Renaming FTP user from {old_ftp_username} to {new_ftp_username}")

                # Check if the new username already exists
                user_check = subprocess.run(['id', new_ftp_username], capture_output=True, text=True)
                if user_check.returncode == 0:
                    messages.error(request, 'The new FTP username already exists')
                    print(f"The new FTP username {new_ftp_username} already exists")
                    return redirect('update_website', website_id=website.id)

                # Rename the user and the group
                print("Renaming the user and the group")
                subprocess.run(['sudo', 'usermod', '-l', new_ftp_username, old_ftp_username], check=True)
                subprocess.run(['sudo', 'groupmod', '-n', new_ftp_username, old_ftp_username], check=True)

                # Rename the user's home directory
                print("Renaming the user's home directory")
                subprocess.run(['sudo', 'mv', f'/home/{old_ftp_username}', f'/home/{new_ftp_username}'], check=True)

                # Adding a delay to ensure the system recognizes the new username and group
                time.sleep(2)

                # Change ownership of new home directory
                print("Changing ownership of new home directory")
                subprocess.run(['sudo', 'chown', '-R', f'{new_ftp_username}:{new_ftp_username}', f'/home/{new_ftp_username}'], check=True)

            if new_ftp_password != website.ftp_password:
                print(f"Changing password for FTP user {new_ftp_username}")
                password_change_result = change_password(new_ftp_username, new_ftp_password)
                if "Error" in password_change_result:
                    messages.error(request, password_change_result)
                    return redirect('update_website', website_id=website.id)
                else:
                    print(password_change_result)

            # Rename the website directory if the website name has changed
            if new_website_name != old_website_name:
                print(f"Renaming website directory from {old_website_name} to {new_website_name}")
                old_website_path = f'/home/{new_ftp_username}/{old_website_name}'
                new_website_path = f'/home/{new_ftp_username}/{new_website_name}'
                if os.path.exists(old_website_path):
                    subprocess.run(['sudo', 'mv', old_website_path, new_website_path], check=True)

                # Update Apache virtual host configuration
                print(f"Updating Apache virtual host configuration from {old_website_name} to {new_website_name}")
                old_apache_conf = f"/etc/apache2/sites-available/{old_website_name}.conf"
                new_apache_conf = f"/etc/apache2/sites-available/{new_website_name}.conf"

                # Move and update the Apache configuration file
                print("Moving and updating the Apache configuration file")
                subprocess.run(['sudo', 'mv', old_apache_conf, new_apache_conf], check=True)

                # Read the updated Apache configuration content
                apache_config_content = f"""
<VirtualHost *:80>
    ServerAdmin webmaster@{new_website_name}
    ServerName {new_website_name}
    DocumentRoot /home/{new_ftp_username}/{new_website_name}/public_html/
    <Directory /home/{new_ftp_username}/{new_website_name}/public_html/>
        AllowOverride all
        Require all granted
        Options FollowSymlinks
        # DirectoryIndex home.html 
        Allow from all
    </Directory>
    ErrorLog /home/{new_ftp_username}/{new_website_name}/logs/error.log
    CustomLog /home/{new_ftp_username}/{new_website_name}/logs/access.log combined
</VirtualHost>
                """

                # Write the updated Apache configuration content back to file
                print("Writing the updated Apache configuration content to file")
                with open('/tmp/temp_apache_conf.conf', 'w') as file:
                    file.write(apache_config_content)
                subprocess.run(['sudo', 'mv', '/tmp/temp_apache_conf.conf', new_apache_conf], check=True)

                # Enable the new site and disable the old site
                print("Enabling the new site and disabling the old site")
                subprocess.run(['sudo', 'a2dissite', f"{old_website_name}.conf"], check=True)
                subprocess.run(['sudo', 'a2ensite', f"{new_website_name}.conf"], check=True)

                # Reload Apache
                print("Reloading Apache")
                subprocess.run(['sudo', 'systemctl', 'reload', 'apache2'], check=True)

                # Update /etc/hosts
                print(f"Updating /etc/hosts from {old_website_name} to {new_website_name}")
                update_hosts_result = update_hosts_file(old_website_name, new_website_name)
                print(update_hosts_result)
                if "Error" in update_hosts_result:
                    messages.error(request, update_hosts_result)
                    return redirect('update_website', website_id=website.id)

            # Update website details in the database
            print("Updating website details in the database")
            website.website_name = new_website_name
            website.ftp_username = new_ftp_username
            website.ftp_password = new_ftp_password
            website.php_version = new_php_version
            website.save()

            print("Website updated successfully")
            messages.success(request, 'Website updated successfully')
            return redirect('list_websites')

        except subprocess.CalledProcessError as e:
            error_message = e.stderr.decode() if e.stderr else str(e)
            print(f"Error updating website: {error_message}")
            messages.error(request, f'Error updating website: {error_message}')
            return redirect('update_website', website_id=website.id)
        except Exception as e:
            print(f"Unexpected error: {str(e)}")
            messages.error(request, f'Unexpected error: {str(e)}')
            return redirect('update_website', website_id=website.id)

    return render(request, 'user/update_website.html', {'website': website , 'user_id':user_id})


logger = logging.getLogger('django')
def update_hosts_file(old_website_name, new_website_name):
    try:
        # Read the existing content of /etc/hosts
        with open('/etc/hosts', 'r') as file:
            hosts_content = file.readlines()

        # Print original content for debugging
        print("Original /etc/hosts content:")
        for line in hosts_content:
            print(line.strip())

        # Update the content
        updated_hosts_content = []
        found = False
        for line in hosts_content:
            if old_website_name in line:
                updated_hosts_content.append(line.replace(old_website_name, new_website_name))
                found = True
                print(f"Replaced '{old_website_name}' with '{new_website_name}' in line: {line.strip()}")
            else:
                updated_hosts_content.append(line)

        if not found:
            updated_hosts_content.append(f"192.168.3.239    {new_website_name}\n")
            print(f"Added new entry for '{new_website_name}' to /etc/hosts")

        updated_hosts_content_str = ''.join(updated_hosts_content)

        # Write updated content back to /etc/hosts using sudo
        with subprocess.Popen(
            ['sudo', 'tee', '/etc/hosts'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        ) as proc:
            stdout, stderr = proc.communicate(input=updated_hosts_content_str.encode())

            if proc.returncode != 0:
                error_message = stderr.decode() if stderr else "Unknown error"
                print(f"Failed to update /etc/hosts: {error_message}")
                logger.error(f"Failed to update /etc/hosts: {error_message}")
                return f"Error: {error_message}"

        print(f"/etc/hosts updated from {old_website_name} to {new_website_name}.")
        return f"/etc/hosts updated from {old_website_name} to {new_website_name}."
    except Exception as e:
        error_message = str(e)
        print(f"Error updating /etc/hosts: {error_message}")
        logger.error(f"Error updating /etc/hosts: {error_message}")
        return f"Error updating /etc/hosts: {error_message}"


@login_required
def delete_website(request, website_id):
    user_id = request.user.id
    website = get_object_or_404(Website, id=website_id)
    if request.method == 'POST':
        website.delete()
        messages.success(request, 'Website deleted successfully')
        return redirect('list_websites')
    return render(request, 'user/confirm_delete.html', {'website': website ,'user_id':user_id})





@csrf_protect
@login_required
def add_customer(request):
    user_id = request.user.id
    
    if request.method == 'POST':
        full_name = request.POST.get('full_name')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        email = request.POST.get('email')
        address1 = request.POST.get('address1')
        address2 = request.POST.get('address2')
        city = request.POST.get('city')
        country = request.POST.get('country')

        # Validate the form data
        if not (full_name and password and confirm_password and email and address1 and city and country):
            messages.error(request, 'Please fill out all required fields')
            return render(request, 'user/add_customer.html')

        if password != confirm_password:
            messages.error(request, 'Passwords do not match')
            return render(request, 'user/add_customer.html')

        # Save data to the database
        customer = Customer(
            full_name=full_name,
            password=password,
            email=email,
            address1=address1,
            address2=address2,
            city=city,
            country=country
        )
        customer.save()

        messages.success(request, 'Customer added successfully')
        return redirect('add_customer')  # Redirect to the same page after success

    return render(request, 'user/add_customer.html', {'user_id': user_id })


import subprocess
import os

def create_ftp_user(ftp_username, ftp_password):
    try:
        # Check if the user already exists
        user_exists = subprocess.run(['id', '-u', ftp_username], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if user_exists.returncode != 0:
            raise Exception(f"FTP user {ftp_username} does not exist. Please create the user first.")

        # Set or update the password for the FTP user
        subprocess.run(['sudo', 'chpasswd'], input=f'{ftp_username}:{ftp_password}'.encode(), check=True)

        # Ensure the vsftpd user configuration directory exists
        vsftpd_user_conf_dir = "/etc/vsftpd/user_conf/"
        subprocess.run(['sudo', 'mkdir', '-p', vsftpd_user_conf_dir], check=True)

        # Create vsftpd configuration for the user
        vsftpd_user_conf = os.path.join(vsftpd_user_conf_dir, ftp_username)
        vsftpd_config_content = f"""
local_root= /home/{ftp_username}
write_enable=YES
local_umask=022
file_open_mode=0755
        """

        with open(vsftpd_user_conf, 'w') as conf_file:
            conf_file.write(vsftpd_config_content)

        # Change the ownership of the configuration file to root:root
        subprocess.run(['sudo', 'chown', 'root:root', vsftpd_user_conf], check=True)

        print(f"FTP configuration for {ftp_username} completed successfully.")
        
    except subprocess.CalledProcessError as e:
        error_message = e.stderr.decode() if e.stderr else str(e)
        raise Exception(f'Error creating FTP user: {error_message}')
    except IOError as e:
        raise Exception(f'Error writing vsftpd configuration file: {str(e)}')

from django.shortcuts import render, redirect, get_object_or_404
from .models import Website
from django.contrib import messages

import os
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages

import os
import logging
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from .models import Website

import os
import subprocess
import logging
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib import messages

import subprocess

# def kill_old_php_processes(current_php_version, ftp_username):
#     """
#     Kill processes related to older PHP-FPM versions for a specific user, based on the current PHP version.

#     Parameters:
#     - current_php_version: The version of PHP that is currently being used (e.g., "8.0").
#     - ftp_username: The username of the user running the PHP processes.
#     """
#     try:
#         # Step 1: List processes for the user
#         result = subprocess.run(
#             ['ps', '-u', ftp_username],
#             capture_output=True,
#             text=True,
#             check=True
#         )

#         # Step 2: Parse the process list
#         lines = result.stdout.strip().split("\n")
#         for line in lines[1:]:  # Skip the header line
#             columns = line.split()
#             pid = columns[0]  # PID is the first column
#             cmd = columns[-1]  # Command is the last column

#             # Check if the command is a PHP-FPM process for an older version (not the current one)
#             if cmd.startswith("php-fpm") and not cmd.endswith(current_php_version):
#                 try:
#                     # Kill the older PHP-FPM process
#                     subprocess.run(['sudo', 'kill', '-9', pid], check=True)
#                     print(f"Killed process {pid} ({cmd}).")
#                 except subprocess.CalledProcessError as kill_error:
#                     print(f"Error killing process {pid}: {kill_error}")

#     except subprocess.CalledProcessError as e:
#         print(f"Command failed: {e}")
#     except Exception as e:
#         print(f"Unexpected error: {e}")




logger = logging.getLogger(__name__)

def update_php_version(request, website_id):
    website = get_object_or_404(Website, id=website_id)
    current_php_version = website.php_version

    if request.method == 'POST':
        new_php_version = request.POST.get('new_php_version')
        if new_php_version:
            try:
                # if current_php_version and current_php_version != new_php_version:
                #     kill_old_php_processes(current_php_version, website.ftp_username)

                # Call your function to install and configure PHP
                install_php_and_configure(website.ftp_username, website.website_name, php_version=new_php_version)
                
                if current_php_version and current_php_version != new_php_version:
                    old_fpm_conf = f"/etc/php/{current_php_version}/fpm/pool.d/{website.ftp_username}.conf"
                    if os.path.exists(old_fpm_conf):
                        print(f"Removing old PHP-FPM configuration: {old_fpm_conf}")
                        subprocess.run(['sudo', 'rm', '-f', old_fpm_conf], check=True)
                    else:
                        print(f"Old PHP-FPM configuration not found: {old_fpm_conf}")
                
                # Define the Apache configuration file path and content
                apache_conf = f"/etc/apache2/sites-available/{website.website_name}.conf"
                temp_apache_conf = f"/tmp/{website.website_name}.conf"
                apache_config_content = f"""
<VirtualHost *:80>
    ServerAdmin webmaster@{website.website_name}
    ServerName {website.website_name}
    DocumentRoot /home/{website.ftp_username}/{website.website_name}/public_html/
    <Directory /home/{website.ftp_username}/{website.website_name}/public_html/>
        AllowOverride all
        Require all granted
        Options FollowSymlinks
        # DirectoryIndex home.html 
        Allow from all
    </Directory>
    ErrorLog /home/{website.ftp_username}/{website.website_name}/logs/error.log
    CustomLog /home/{website.ftp_username}/{website.website_name}/logs/access.log combined
    # Configure PHP-FPM
    <FilesMatch \.php$>
        SetHandler "proxy:unix:/run/php/php{new_php_version}-fpm-{website.ftp_username}.sock|fcgi://localhost"
    </FilesMatch>
</VirtualHost>
                """
                
                # Write to the temporary file
                with open(temp_apache_conf, 'w') as f:
                    f.write(apache_config_content)

                # Change permissions of the temporary file
                os.chmod(temp_apache_conf, 0o644)

                # Move the temporary file to the Apache configuration directory
                result = subprocess.run(['sudo', 'mv', temp_apache_conf, apache_conf], capture_output=True, text=True)
                if result.returncode != 0:
                    raise Exception(f"Failed to move configuration file: {result.stderr}")

                php_fpm_service = f'php{new_php_version}-fpm'
                result = subprocess.run(['sudo', 'systemctl', 'restart', php_fpm_service], capture_output=True, text=True)
                if result.returncode != 0:
                    raise Exception(f"Failed to restart PHP-FPM service: {result.stderr}")

                # Reload Apache to apply the changes
                # result = subprocess.run(['sudo', 'systemctl', 'reload', 'apache2'], capture_output=True, text=True)
                # if result.returncode != 0:
                #     raise Exception(f"Failed to reload Apache: {result.stderr}")

                # Update the PHP version in the database
                website.php_version = new_php_version
                website.save()

                messages.success(request, 'PHP version updated successfully and Apache configuration updated.')
            except Exception as e:
                logger.error(f"Failed to update Apache configuration: {e}")
                messages.error(request, f"Failed to update Apache configuration: {e}")

            return redirect('update_php_version', website_id=website_id)

    return render(request, 'user/update_php_version.html', {'website': website, 'current_php_version': current_php_version})

# import subprocess

# def get_latest_php_version():
#     """
#     Fetch the latest PHP version available for installation.
#     """
#     try:
#         # Check available PHP versions
#         output = subprocess.check_output(['apt-cache', 'search', 'php-fpm'], stderr=subprocess.STDOUT).decode()
#         php_versions = [line.split()[0] for line in output.splitlines() if 'php' in line and '-fpm' in line]
#         php_versions = sorted(php_versions, reverse=True)  # Sort in descending order to get the latest version first
#         if php_versions:
#             latest_version = php_versions[0].replace('php', '').replace('-fpm', '')
#             return latest_version
#         else:
#             print("No PHP versions found.")
#             return None
#     except Exception as e:
#         print(f"Error fetching latest PHP version: {e}")
#         return None


# def install_php_and_configure(ftp_username, domain_name, subdomain_name=None, php_version=None):
#     """
#     Install PHP and configure PHP-FPM for the given user and (sub)domain.

#     Args:
#         ftp_username (str): The FTP username for which PHP should be configured.
#         domain_name (str): The domain name for the website.
#         subdomain_name (str): Optional. The subdomain name, if configuring for a subdomain.
#         php_version (str): Optional. The PHP version to install and configure. It must be provided explicitly.
#     """
#     if subdomain_name:
#         # If it's a subdomain, use the latest PHP version
#         print(f"Fetching latest PHP version for subdomain {subdomain_name}...")
#         php_version = get_latest_php_version()
#         if not php_version:
#             print("Error: Could not fetch the latest PHP version.")
#             return
#     else:
#         # For main domain, ensure php_version is provided
#         if not php_version:
#             print("Error: PHP version is required for main domain.")
#             return

#     try:
#         # Install PHP version and PHP-FPM
#         print(f"Installing PHP {php_version} for {'subdomain' if subdomain_name else 'main domain'}...")
#         distro_info = subprocess.check_output(['lsb_release', '-a'], stderr=subprocess.STDOUT).decode()
        
#         if 'Ubuntu' in distro_info:
#             subprocess.run(['sudo', 'apt', 'update'], check=True)
#             subprocess.run(['sudo', 'apt', 'install', '-y', f'php{php_version}', f'php{php_version}-fpm'], check=True)
#         elif 'CentOS' in distro_info or 'RedHat' in distro_info:
#             subprocess.run(['sudo', 'yum', 'install', '-y', f'php{php_version}', f'php{php_version}-fpm'], check=True)
#         else:
#             print("Unsupported distribution.")
#             return

#         # Check if configuring for a subdomain or just the main domain
#         if subdomain_name:
#             config_name = f"{ftp_username}-{subdomain_name}.{domain_name}"
#         else:
#             config_name = f"{ftp_username}"

#         print(f"Configuring PHP-FPM for {config_name}...")

#         # PHP-FPM pool configuration path
#         fpm_conf = f'/etc/php/{php_version}/fpm/pool.d/{config_name}.conf'
#         print(f"Config file path: {fpm_conf}")

#         # Create the content for the PHP-FPM pool configuration file
#         fpm_config_content = f"""
# [{config_name}]
# user = {ftp_username}
# group = {ftp_username}
# listen = /run/php/php{php_version}-fpm-{config_name}.sock
# listen.owner = www-data
# listen.group = www-data
# listen.mode = 0660
# pm = dynamic
# pm.max_children = 5
# pm.start_servers = 2
# pm.min_spare_servers = 1
# pm.max_spare_servers = 3
# chdir = /
#         """

#         print(f"Creating temporary config file for {config_name}...")
#         # Write the configuration to a temporary file
#         temp_conf_file = f'/tmp/{config_name}.conf'
#         with open(temp_conf_file, 'w') as f:
#             f.write(fpm_config_content)

#         print(f"Moving the config file to the correct location: {fpm_conf}")
#         # Move the temporary file to the target location
#         subprocess.run(['sudo', 'mv', temp_conf_file, fpm_conf], check=True)
#         subprocess.run(['sudo', 'chown', 'root:root', fpm_conf], check=True)
#         subprocess.run(['sudo', 'chmod', '644', fpm_conf], check=True)

#         # Ensure PHP-FPM service is running and reload it
#         php_fpm_service = f'php{php_version}-fpm'
#         print(f"Starting and reloading PHP-FPM service: {php_fpm_service}")
#         subprocess.run(['sudo', 'systemctl', 'start', php_fpm_service], check=True)
#         subprocess.run(['sudo', 'systemctl', 'enable', php_fpm_service], check=True)
#         subprocess.run(['sudo', 'systemctl', 'reload', php_fpm_service], check=True)

#         print(f"PHP {php_version} installed and configured for {config_name} (user: {ftp_username}).")

#     except subprocess.CalledProcessError as e:
#         print(f"Error during PHP installation or configuration: {e}")
#     except Exception as e:
#         print(f"Unexpected error: {e}")


def install_php_and_configure(ftp_username, domain_name, subdomain_name=None, php_version=None):
    # Ensure PHP version is provided or valid
    if not php_version:
        print("Error: PHP version is required.")
        return

    try:
        # Install the specified PHP version and PHP-FPM
        print(f"Installing PHP {php_version} for {'subdomain' if subdomain_name else 'main domain'}...")
        distro_info = subprocess.check_output(['lsb_release', '-a'], stderr=subprocess.STDOUT).decode()

        if 'Ubuntu' in distro_info:
            subprocess.run(['sudo', 'apt', 'update'], check=True)
            subprocess.run(['sudo', 'apt', 'install', '-y', f'php{php_version}', f'php{php_version}-fpm'], check=True)
        elif 'CentOS' in distro_info or 'RedHat' in distro_info:
            subprocess.run(['sudo', 'yum', 'install', '-y', f'php{php_version}', f'php{php_version}-fpm'], check=True)
        else:
            print("Unsupported distribution.")
            return

        # Determine the configuration name and file path
        if subdomain_name:
            config_name = f"{ftp_username}-{subdomain_name}.{domain_name}"
            fpm_conf = f'/etc/php/{php_version}/fpm/pool.d/{ftp_username}-{subdomain_name}.conf'
        else:
            config_name = ftp_username
            fpm_conf = f'/etc/php/{php_version}/fpm/pool.d/{ftp_username}.conf'

        print(f"Configuring PHP-FPM for {config_name}...")

        # Create the content for the PHP-FPM pool configuration file
        fpm_config_content = f"""
[{config_name}]
user = {ftp_username}
group = {ftp_username}
listen = /run/php/php{php_version}-fpm-{config_name}.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
chdir = /
        """

        print(f"Creating temporary config file for {config_name}...")
        # Write the configuration to a temporary file
        temp_conf_file = f'/tmp/{config_name}.conf'
        with open(temp_conf_file, 'w') as f:
            f.write(fpm_config_content)

        print(f"Moving the config file to the correct location: {fpm_conf}")
        # Move the temporary file to the target location
        subprocess.run(['sudo', 'mv', temp_conf_file, fpm_conf], check=True)
        subprocess.run(['sudo', 'chown', 'root:root', fpm_conf], check=True)
        subprocess.run(['sudo', 'chmod', '644', fpm_conf], check=True)

        # Ensure PHP-FPM service is running and reload it
        php_fpm_service = f'php{php_version}-fpm'
        print(f"Starting and reloading PHP-FPM service: {php_fpm_service}")
        subprocess.run(['sudo', 'systemctl', 'start', php_fpm_service], check=True)
        subprocess.run(['sudo', 'systemctl', 'enable', php_fpm_service], check=True)
        subprocess.run(['sudo', 'systemctl', 'reload', php_fpm_service], check=True)

        print(f"PHP {php_version} installed and configured for {config_name} (user: {ftp_username}).")

    except subprocess.CalledProcessError as e:
        print(f"Error during PHP installation or configuration: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

# Example usage:
# Pass the new PHP version dynamically during function call
# install_php_and_configure(website.ftp_username, website.website_name, php_version=new_php_version)


from django.shortcuts import render, redirect
from django.contrib import messages

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .models import Website  
import subprocess
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .models import Website

from django.shortcuts import get_object_or_404, redirect, render
from django.contrib import messages
from django.db import connection
import subprocess

from django.shortcuts import redirect
from django.http import HttpResponseBadRequest
# import requests
from django.http import HttpResponseBadRequest, HttpResponse
from django.shortcuts import redirect

# import requests
from django.http import HttpResponseBadRequest, HttpResponseRedirect
# import requests
from django.http import HttpResponseRedirect, HttpResponseBadRequest

# import requests
from django.http import HttpResponseRedirect, HttpResponseBadRequest

# import requests
from django.http import HttpResponseRedirect, HttpResponseBadRequest
from django.urls import reverse

def redirect_to_phpmyadmin(request):
    db_name = request.GET.get('db')
    db_user = request.GET.get('pma_username')
    db_password = request.GET.get('pma_password')

    if not db_name or not db_user or not db_password:
        return HttpResponseBadRequest("Missing required parameters")

    # phpMyAdmin login URL
    phpmyadmin_url = 'http://192.168.3.239/phpmyadmin/index.php'
    
    # Create a session object
    session = requests.Session()

    # Step 1: Get the phpMyAdmin login page to retrieve the CSRF token
    login_page = session.get(phpmyadmin_url)
    soup = BeautifulSoup(login_page.text, 'html.parser')

    # Find the CSRF token from the login page
    token_input = soup.find('input', {'name': 'token'})
    csrf_token = token_input['value'] if token_input else None
    print(f"Token Input: {token_input}")
    print(f"CSRF Token: {csrf_token}")

    if not csrf_token:
        return redirect('/')  # If no CSRF token found, handle the error
    
    # Data for logging in
    login_data = {
        'pma_username': db_user,
        'pma_password': db_password,
        'db': db_name,
        'token': csrf_token,
        'token_input': str(token_input),
        'Submit': 'Go'
    }

    # Perform the login
    response = session.post(phpmyadmin_url, data=login_data)

    # Check if login was successful
    if response.ok and 'phpMyAdmin' in response.text:
        # Construct the redirect URL based on the database details
        redirect_url = f"http://192.168.3.239/phpmyadmin/index.php?db={db_name}"
        return HttpResponseRedirect(redirect_url)
    else:
        return HttpResponseBadRequest("Login failed")

import subprocess
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages

def remove_database(request, website_id, database_id):
    if request.method == 'POST':
        database = get_object_or_404(Database, id=database_id, website_id=website_id)

        # Fetch database credentials from the database_details table
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT username, password FROM database_detials WHERE id = 1;")
                result = cursor.fetchone()
                if result:
                    username, password = result
                    print(f"Username: {username}, Password: {password}")
                else:
                    raise RuntimeError("Database credentials not found in the database_details table.")

            # Use the mysql command-line client to execute the DROP DATABASE command
            command = f"mysql -u {username} -p{password} -e 'DROP DATABASE {database.name};'"
            process = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)

            commands = f"mysql -u {username} -p{password} -e 'DROP USER \"{database.user}\"@\"localhost\";'"
            print(f"Database user to be dropped: {database.user}")
            process = subprocess.run(commands, shell=True, check=True, capture_output=True, text=True)

            # Check for errors
            if process.returncode == 0:
                messages.success(request, f"Database '{database.name}' has been removed successfully.")
            else:
                messages.error(request, f"There was an error removing the database: {process.stderr}")

        except subprocess.CalledProcessError as e:
            messages.error(request, f"There was an error executing the MySQL command: {e}")

        except Exception as e:
            messages.error(request, f"There was an error removing the database: {str(e)}")

        # Delete the database instance from your Django model
        database.delete()

        return redirect('list_databases', website_id=website_id)
    else:
        return redirect('list_databases', website_id=website_id)



def add_database(request, website_id):
    # Fetch the website object based on the provided website_id
    selected_website = get_object_or_404(Website, id=website_id)

    if request.method == "POST":
        # Retrieve the input values from the POST request
        database_name = request.POST.get('database_name')
        database_user = request.POST.get('database_user')
        database_password = request.POST.get('database_password')

        if database_name and database_user and database_password:
            try:
                # Count existing databases for this website
                existing_databases = Database.objects.filter(website=selected_website).count()
                database_limit = selected_website.database_allowed

                print(f"Existing Databases: {existing_databases}")
                print(f"Database Limit: {database_limit}")

                if existing_databases >= database_limit:
                    messages.error(request, "Database creation limit reached. Please delete an existing database before creating a new one.")
                    print("Database creation limit reached.")
                else:
                    # Retrieve root database credentials
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT username, password FROM database_detials WHERE id = 1;")
                        result = cursor.fetchone()
                        if result:
                            username, password = result
                        else:
                            raise RuntimeError("Database credentials not found in the database_detials table.")

                    mysql_command = ['mysql', '-u', username, f'-p{password}']

                    # Create the database
                    subprocess.run(
                        mysql_command + ['-e', f"CREATE DATABASE {database_name};"],
                        check=True, capture_output=True, text=True
                    )

                    # Create the database user
                    subprocess.run(
                        mysql_command + ['-e', f"CREATE USER '{database_user}'@'localhost' IDENTIFIED BY '{database_password}';"],
                        check=True, capture_output=True, text=True
                    )

                    # Grant all privileges to the new user on the new database
                    subprocess.run(
                        mysql_command + ['-e', f"GRANT ALL PRIVILEGES ON {database_name}.* TO '{database_user}'@'localhost';"],
                        check=True, capture_output=True, text=True
                    )

                    # Flush privileges to ensure all changes take effect
                    subprocess.run(
                        mysql_command + ['-e', "FLUSH PRIVILEGES;"],
                        check=True, capture_output=True, text=True
                    )

                    # Save database details to the Database model
                    Database.objects.create(  # Updated line
                        website=selected_website,
                        name=database_name,
                        user=database_user,
                        password=database_password
                    )

                    messages.success(request, f"Database {database_name} created successfully!")
                    return redirect('add_database', website_id=selected_website.id)
            except subprocess.CalledProcessError as e:
                error_message = e.stderr if e.stderr else str(e)
                messages.error(request, f"An error occurred while creating the database and user: {error_message}")
                print(f"Subprocess Error: {error_message}")
            except Exception as e:
                # Handle other exceptions
                messages.error(request, f"An unexpected error occurred: {str(e)}")
                print(f"Unexpected Error: {str(e)}")
        else:
            messages.error(request, "All fields are required.")

    return render(request, 'user/add_database.html', {'website': selected_website})



# from django.shortcuts import get_object_or_404, redirect, render
# from django.contrib import messages
# from django.db import connection
# import subprocess


# def add_database(request, website_id):
#     # Fetch the website object based on the provided website_id
#     selected_website = get_object_or_404(Website, id=website_id)

#     if request.method == "POST":
#         # Retrieve the input values from the POST request
#         database_name = request.POST.get('database_name')
#         database_user = request.POST.get('database_user')
#         database_password = request.POST.get('database_password')

#         if database_name and database_user and database_password:
#             try:
#                 # Count existing databases for this website
#                 existing_databases = Database.objects.filter(website=selected_website).count()

#                 # Fetch the database limit for the website
#                 database_limit = selected_website.database_allowed

#                 if existing_databases >= database_limit:
#                     messages.error(request, "Database creation limit reached. Please delete an existing database before creating a new one.")
#                 else:
#                     # Retrieve root database credentials from database_details table
#                     with connection.cursor() as cursor:
#                         cursor.execute("SELECT username, password FROM database_detials WHERE id = 1;")
#                         result = cursor.fetchone()
#                         if result:
#                             username, password = result
#                         else:
#                             raise RuntimeError("Database credentials not found in the database_detials table.")

#                     # MySQL command prefix with root credentials
#                     mysql_command = ['mysql', '-u', username, f'-p{password}']

#                     # Create the database
#                     subprocess.run(
#                         mysql_command + ['-e', f"CREATE DATABASE {database_name};"],
#                         check=True, capture_output=True, text=True
#                     )

#                     # Create the database user
#                     subprocess.run(
#                         mysql_command + ['-e', f"CREATE USER '{database_user}'@'localhost' IDENTIFIED BY '{database_password}';"],
#                         check=True, capture_output=True, text=True
#                     )

#                     # Grant all privileges to the new user on the new database
#                     subprocess.run(
#                         mysql_command + ['-e', f"GRANT ALL PRIVILEGES ON {database_name}.* TO '{database_user}'@'localhost';"],
#                         check=True, capture_output=True, text=True
#                     )

#                     # Flush privileges to ensure all changes take effect
#                     subprocess.run(
#                         mysql_command + ['-e', "FLUSH PRIVILEGES;"],
#                         check=True, capture_output=True, text=True
#                     )

#                     # Save database details to the Database model
#                     Database.objects.create(
#                         website=selected_website,
#                         name=database_name,
#                         user=database_user,
#                         password=database_password
#                     )

#                     messages.success(request, f"Database {database_name} created successfully!")
#                     # Redirect to the website details page
#                     return redirect('add_database', website_id=selected_website.id)
#             except subprocess.CalledProcessError as e:
#                 # Handle errors in the subprocess execution
#                 error_message = e.stderr if e.stderr else str(e)
#                 messages.error(request, f"An error occurred while creating the database and user: {error_message}")
#         else:
#             # Display an error message if required fields are missing
#             messages.error(request, "All fields are required.")

#     # Render the add database template
#     return render(request, 'user/add_database.html', {'website': selected_website})



# def add_database(request, website_id):
#     # Fetch the website object based on the provided website_id
#     selected_website = get_object_or_404(Website, id=website_id)

#     if request.method == "POST":
#         # Retrieve the input values from the POST request
#         database_name = request.POST.get('database_name')
#         database_user = request.POST.get('database_user')
#         database_password = request.POST.get('database_password')

#         if database_name and database_user and database_password:
#             try:
#                 # Retrieve root database credentials from database_details table
#                 with connection.cursor() as cursor:
#                     cursor.execute("SELECT username, password FROM database_detials WHERE id = 1;")
#                     result = cursor.fetchone()
#                     if result:
#                         username, password = result
#                     else:
#                         raise RuntimeError("Database credentials not found in the database_details table.")

#                 # MySQL command prefix with root credentials
#                 mysql_command = ['mysql', '-u', username, f'-p{password}']

#                 # Create the database
#                 subprocess.run(
#                     mysql_command + ['-e', f"CREATE DATABASE {database_name};"],
#                     check=True, capture_output=True, text=True
#                 )

#                 # Create the database user
#                 subprocess.run(
#                     mysql_command + ['-e', f"CREATE USER '{database_user}'@'localhost' IDENTIFIED BY '{database_password}';"],
#                     check=True, capture_output=True, text=True
#                 )

#                 # Grant all privileges to the new user on the new database
#                 subprocess.run(
#                     mysql_command + ['-e', f"GRANT ALL PRIVILEGES ON {database_name}.* TO '{database_user}'@'localhost';"],
#                     check=True, capture_output=True, text=True
#                 )

#                 # Flush privileges to ensure all changes take effect
#                 subprocess.run(
#                     mysql_command + ['-e', "FLUSH PRIVILEGES;"],
#                     check=True, capture_output=True, text=True
#                 )

#                 print(f"Database Name: {database_name}")
#                 print(f"Database User: {database_user}")
#                 print(f"Database Password: {database_password}")

#                 # Display a success message
#                 messages.success(request, f"Database {database_name} created successfully!")
#                 # Redirect to the website details page
#                 return redirect('add_database', website_id=selected_website.id)
#             except subprocess.CalledProcessError as e:
#                 # Handle errors in the subprocess execution
#                 error_message = e.stderr if e.stderr else str(e)
#                 messages.error(request, f"An error occurred while creating the database and user: {error_message}")
#         else:
#             # Display an error message if required fields are missing
#             messages.error(request, "All fields are required.")

#     # Render the add database template
#     return render(request, 'user/add_database.html', {'website': selected_website})


from django.shortcuts import render, get_object_or_404
from popo.models import Website

def list_databases(request, website_id):
    website = get_object_or_404(Website, id=website_id)
    databases = Database.objects.filter(website=website)
    
    context = {
        'website': website,
        'databases': databases,
    }
    return render(request, 'user/list_databases.html', context)

# views.py
from django.shortcuts import render

def ssl_page(request, website_id):
    # Fetch the website information using the website_id if needed
    # Example: website = Website.objects.get(id=website_id)
    
    return render(request, 'user/ssl_page.html', {'website_id': website_id})






import os
import subprocess
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from .models import Website
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import os
import subprocess
from django.contrib import messages
from django.shortcuts import redirect
import os
import subprocess

@csrf_exempt
def setup_domain(request):
    if request.method == 'POST':
        website_id = request.POST.get('website_id')

        if not website_id:
            print("Error: Website ID is required")
            return JsonResponse({'error': 'Website ID is required'}, status=400)
        try:
            print(f"Fetching website details for ID: {website_id}")
            website = Website.objects.get(id=website_id)

            website_name = website.website_name
            ftp_username = website.ftp_username
            php_version = website.php_version
            print(f"Website details retrieved: {website_name}, FTP Username: {ftp_username}")

            public_html_path = f"/home/{ftp_username}/{website_name}/public_html"
            index_html_path = os.path.join(public_html_path, "index.html")
            
            if not os.path.exists(public_html_path):
                os.makedirs(public_html_path, exist_ok=True)
            
            print(f"Setting permissions for {public_html_path} to 777...")
            subprocess.run(['sudo', 'chmod', '-R', '777', public_html_path], check=True)
            print(f"Successfully set permissions for {public_html_path} to 777")

            if not os.path.exists(index_html_path):
                with open(index_html_path, 'w') as index_file:
                    index_file.write("<html><body><h1>Welcome to your website!</h1></body></html>")

            
            print("Updating package list...")
            subprocess.run(['sudo', 'apt', 'update'], check=True)
            print("Installing Certbot and Apache modules...")
            subprocess.run(['sudo', 'apt', 'install', '-y', 'certbot', 'python3-certbot-apache'], check=True)
            subprocess.run(['sudo', 'a2enmod', 'ssl'], check=True)
            subprocess.run(['sudo', 'a2enmod', 'rewrite'], check=True)

 
            subprocess.run(['sudo', 'chmod', '-R', '777', '/etc/apache2/sites-available/'], check=True)
            print("Successfully set permissions for /etc/apache2/sites-available/")
            
            website_conf_path = f'/etc/apache2/sites-available/{website_name}.conf'
            print(f"Setting permissions for {website_conf_path}...")
            subprocess.run(['sudo', 'chmod', '-R', '777', website_conf_path], check=True)
            print(f"Successfully set permissions for {website_conf_path}")
                        
            print("Preparing VirtualHost configuration...")
            vhost_content = f"""<VirtualHost *:80>
    ServerAdmin webmaster@{website_name}
    ServerName {website_name}
    DocumentRoot /home/{ftp_username}/{website_name}/public_html

    <Directory /home/{ftp_username}/{website_name}/public_html>
        AllowOverride All
        Require all granted
        Options FollowSymLinks
        DirectoryIndex index.html index.php
    </Directory>

    ErrorLog /home/{ftp_username}/{website_name}/logs/error.log
    CustomLog /home/{ftp_username}/{website_name}/logs/access.log combined

    # Redirect HTTP to HTTPS
    Redirect permanent / https://{website_name}/
</VirtualHost>

<VirtualHost *:443>
    ServerAdmin webmaster@{website_name}
    ServerName {website_name}
    DocumentRoot /home/{ftp_username}/{website_name}/public_html

    <Directory /home/{ftp_username}/{website_name}/public_html>
        AllowOverride All
        Require all granted
        Options FollowSymLinks
        DirectoryIndex index.html index.php
    </Directory>

    ErrorLog /home/{ftp_username}/{website_name}/logs/error.log
    CustomLog /home/{ftp_username}/{website_name}/logs/access.log combined

    # SSL settings
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/{website_name}/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/{website_name}/privkey.pem
    Include /etc/letsencrypt/options-ssl-apache.conf

    # PHP-FPM configuration
    <FilesMatch \\.php$>
        SetHandler "proxy:unix:/run/php/php{php_version}-fpm-{ftp_username}.sock|fcgi://localhost"
    </FilesMatch>
</VirtualHost>
"""

            # Write the configuration to the Apache sites-available directory
            vhost_file_path = f'/etc/apache2/sites-available/{website_name}.conf'
            print(f"Writing VirtualHost configuration to {vhost_file_path}...")
            with open(vhost_file_path, 'w') as vhost_file:
                vhost_file.write(vhost_content)

            subprocess.run(['sudo', 'chown', 'root:root', vhost_file_path], check=True)

            # Enable Apache site configuration
            subprocess.run(['sudo', 'a2ensite', f'{website_name}.conf'], check=True)

            # Enable the new site
            print(f"Enabling site configuration: {website_name}.conf")
            subprocess.run(['sudo', 'a2ensite', f'{website_name}.conf'], check=True)

            # Reload Apache to apply changes
            print("Reloading Apache to apply changes...")
            # subprocess.run(['sudo', 'systemctl', 'reload', 'apache2'], check=True)

            # Obtain SSL certificate for the website
            print("Obtaining SSL certificate...")
            subprocess.run(['sudo', 'certbot', '--apache', '--non-interactive', '--agree-tos', '-m', f'webmaster@{website_name}', '-d', website_name], check=True)

            messages.success(request, "SSL certificate successfully installed.")
            # Redirect to ssl_page.html after success
            return redirect('ssl_page' , website_id=website_id)  # Make sure 'ssl_page' is the correct name of your URL pattern

        except Website.DoesNotExist:
            print(f"Error: Website with ID {website_id} not found.")
            return JsonResponse({'error': 'Website not found'}, status=404)
        except PermissionError:
            print("Error: Permission denied. Ensure the application has access to write to Apache configuration files.")
            return JsonResponse({'error': 'Permission denied. Ensure the application has access to write to Apache configuration files.'}, status=403)
        except subprocess.CalledProcessError as e:
            print(f"Error during subprocess execution: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)

    print("Error: Invalid request method")
    return JsonResponse({'error': 'Invalid request method'}, status=405)




import random
import string
from django.db import connection

def create_database_and_user(ftp_username, website_name, length=8):
    # Retrieve root database credentials from database_details table
    with connection.cursor() as cursor:
        cursor.execute("SELECT username, password FROM database_detials WHERE id = 1;")
        result = cursor.fetchone()
        if result:
            username, password = result
            print(f"Root Username: {username}")
            print(f"Root Password: {password}")
        else:
            raise RuntimeError("Database credentials not found in the database_detials table.")

    # Generate random database, user, and password
    db_name = f"db_{''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6))}"
    db_user = f"user_{''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6))}"
    db_pass = ''.join(random.choice(string.ascii_letters ) for _ in range(length))

    try:
        # Print generated values
        print(f"Database Name: {db_name}")
        print(f"Database User: {db_user}")
        print(f"Database Password: {db_pass}")

        # MySQL command prefix with root credentials
        mysql_command = ['mysql', '-u', username, f'-p{password}']

        # Create database
        result = subprocess.run(
            mysql_command + ['-e', f"CREATE DATABASE {db_name};"],
            check=True, capture_output=True, text=True
        )
        print("Create Database Output:", result.stdout)

        # Create user
        result = subprocess.run(
            mysql_command + ['-e', f"CREATE USER '{db_user}'@'localhost' IDENTIFIED BY '{db_pass}';"],
            check=True, capture_output=True, text=True
        )
        print("Create User Output:", result.stdout)

        # Grant privileges
        result = subprocess.run(
            mysql_command + ['-e', f"GRANT ALL PRIVILEGES ON {db_name}.* TO '{db_user}'@'localhost';"],
            check=True, capture_output=True, text=True
        )
        print("Grant Privileges Output:", result.stdout)

        # Flush privileges
        result = subprocess.run(
            mysql_command + ['-e', "FLUSH PRIVILEGES;"],
            check=True, capture_output=True, text=True
        )
        print("Flush Privileges Output:", result.stdout)

        Dbuserpass.objects.create(
            ftp_username=ftp_username,
            website_name=website_name,
            db_name=db_name,
            db_user=db_user,
            db_pass=db_pass
        )
        print("Database information saved successfully.")
        

        return {
            'db_name': db_name,
            'db_user': db_user,
            'db_pass': db_pass,
        }

    except subprocess.CalledProcessError as e:
        error_message = e.stderr if e.stderr else str(e)
        raise RuntimeError(f"An error occurred while creating the database and user: {error_message}")



from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Website, Subdomain  # Assuming Subdomain is a new model

import random
import string
import subprocess
import logging
import os
import random
import string
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .models import Website, Subdomain

import subprocess
import tempfile
import random
import string
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .models import Website, Subdomain

@login_required
def add_subdomain(request, website_id):
    website = get_object_or_404(Website, id=website_id)

    if request.method == 'POST':
        subdomain_name = request.POST.get('subdomain_name')
        php_version = website.php_version  # Use the PHP version from the main website

        if not subdomain_name:
            messages.error(request, 'Please provide a subdomain name.')
            return redirect('add_subdomain', website_id=website_id)
        try:
            subdomain_full_name = f"{subdomain_name}.{website.website_name}"
            

            # Create subdomain directories
            subprocess.run(['sudo', 'mkdir', '-p', f'/home/{website.ftp_username}/{subdomain_full_name}/public_html', f'/home/{website.ftp_username}/{subdomain_full_name}/logs'], check=True)  

            # Update DNS and Apache
            subprocess.run(['sudo', 'sh', '-c', f'echo "192.168.3.239    {subdomain_full_name}" >> /etc/hosts'], check=True)

            # Apache configuration
            apache_conf = f"/etc/apache2/sites-available/{subdomain_full_name}.conf"
            apache_config_content = f"""
<VirtualHost *:80>
    ServerAdmin webmaster@{subdomain_full_name}
    ServerName {subdomain_full_name}
    DocumentRoot /home/{website.ftp_username}/{subdomain_full_name}/publ'ic_html/
    <Directory /home/{website.ftp_username}/{subdomain_full_name}/public_html/>
        AllowOverride all
        Require all granted
        Options FollowSymlinks
    </Directory>
    ErrorLog /home/{website.ftp_username}/{subdomain_full_name}/logs/error.log
    CustomLog /home/{website.ftp_username}/{subdomain_full_name}/logs/access.log combined
    <FilesMatch \.php$>
        SetHandler "proxy:unix:/run/php/php{php_version}-fpm-{subdomain_full_name}.sock|fcgi://localhost"
    </FilesMatch>
</VirtualHost>
            """
            with open(apache_conf, 'w') as f:
                f.write(apache_config_content)
            subprocess.run(['sudo', 'chown', 'root:root', apache_conf], check=True)

            # Generate FTP credentials
            subdomain_ftpuser = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
            subdomain_ftppass = ''.join(random.choices(string.ascii_letters + string.digits, k=5))

            # FTP user creation
            subprocess.run(['sudo', 'useradd', '-m', '-s', '/bin/false', subdomain_ftpuser], check=True)
            subprocess.run(['sudo', 'bash', '-c', f'echo "{subdomain_ftpuser}:{subdomain_ftppass}" | sudo chpasswd'], check=True)

            # Vsftpd user configuration
            vsftpd_user_conf = f"/etc/vsftpd/user_conf/{subdomain_ftpuser}.conf"
            vsftpd_config_content = f"""
local_root=/home/{website.ftp_username}/{subdomain_full_name}
write_enable=YES    
local_umask=022
file_open_mode=0755
            """ 
            with open(vsftpd_user_conf, 'w') as conf_file:
                conf_file.write(vsftpd_config_content)

            subprocess.run(['sudo', 'chown', 'root:root', vsftpd_user_conf], check=True)

            # Set permissions for subdomain
            subprocess.run(['sudo', 'chmod', '-R', '775', f'/home/{website.ftp_username}/{subdomain_full_name}'], check=True)
            subprocess.run(['sudo', 'chown', '-R', f'{subdomain_ftpuser}:{website.ftp_username}', f'/home/{website.ftp_username}/{subdomain_full_name}'], check=True)

            # PHP-FPM pool configuration with unique socket
            php_fpm_config_content = f"""
[{subdomain_full_name}]
user = {website.ftp_username}
group = {website.ftp_username}
listen = /run/php/php{php_version}-fpm-{subdomain_full_name}.sock
listen.owner = www-data
listen.group = www-data
pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
            """
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file.write(php_fpm_config_content.encode())
                temp_file_path = temp_file.name

            # Move temporary file to PHP-FPM pool directory
            php_fpm_conf = f"/etc/php/{php_version}/fpm/pool.d/{subdomain_full_name}.conf"
            subprocess.run(['sudo', 'mv', temp_file_path, php_fpm_conf], check=True)
            subprocess.run(['sudo', 'chown', 'root:root', php_fpm_conf], check=True)

            # Enable site and reload services
            subprocess.run(['sudo', 'a2ensite', f'{subdomain_full_name}.conf'], check=True)
            subprocess.run(['sudo', 'systemctl', 'reload', 'apache2'], check=True)
            subprocess.run(['sudo', 'systemctl', 'restart', f'php{php_version}-fpm'], check=True)

            # Save subdomain instance to the database
            # customer_instance = website.customer

            # website = Website(
            #     customer=customer_instance,
            #     website_name=subdomain_full_name,
            #     ftp_username=subdomain_ftpuser,
            #     ftp_password=subdomain_ftppass,
            #     php_version=php_version,
            #     database_allowed=1  # Set to your desired value
            # )
            # website.save()

            subdomain = Subdomain(
                website=website,
                subdomain_name=subdomain_full_name,
                php_version=php_version,
                subdomainftpuser=subdomain_ftpuser,
                subdomainftppass=subdomain_ftppass
            )
            subdomain.save()

            messages.success(request, f'Subdomain created successfully. FTP Username: {subdomain_ftpuser}, Password: {subdomain_ftppass}')
            return redirect('add_subdomain', website_id=website_id)

        except subprocess.CalledProcessError as e:
            messages.error(request, f'Error while creating subdomain: Command failed with return code {e.returncode}.')
        except Exception as e:
            messages.error(request, f'Error while creating subdomain: {str(e)}')
        
        return redirect('website_info', id=website_id)

    php_versions = ['7.4', '8.0', '8.1']  # Available PHP versions
    return render(request, 'user/add_subdomain.html', {'website': website, 'php_versions': php_versions})

# # Configure logging
# logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# @login_required
# def add_subdomain(request, website_id):
#     website = get_object_or_404(Website, id=website_id)
    
#     if request.method == 'POST':
#         subdomain_name = request.POST.get('subdomain_name')
#         php_version = request.POST.get('php_version', '8.3')  # Default to PHP 8.3
#         # php_version = website.php_version
        
#         if not subdomain_name:
#             messages.error(request, 'Please provide a subdomain name.')
#             return redirect('add_subdomain', website_id=website_id)
        
#         try:
#             subdomain_full_name = f"{subdomain_name}.{website.website_name}"

#             # Create subdomain directories
#             subprocess.run(['sudo', 'mkdir', '-p', f'/home/{website.ftp_username}/{subdomain_full_name}/public_html', f'/home/{website.ftp_username}/{subdomain_full_name}/logs'], check=True)
            
#             # Update DNS and Apache
#             subprocess.run(['sudo', 'sh', '-c', f'echo "192.168.3.239    {subdomain_full_name}" >> /etc/hosts'], check=True)
            
#             apache_conf = f"/etc/apache2/sites-available/{subdomain_full_name}.conf"
#             apache_config_content = f"""
# <VirtualHost *:80>
#     ServerAdmin webmaster@{subdomain_full_name}
#     ServerName {subdomain_full_name}
#     DocumentRoot /home/{website.ftp_username}/{subdomain_full_name}/public_html/
#     <Directory /home/{website.ftp_username}/{subdomain_full_name}/public_html/>
#         AllowOverride all
#         Require all granted
#         Options FollowSymlinks
#         # DirectoryIndex home.html
#     </Directory>
#     ErrorLog /home/{website.ftp_username}/{subdomain_full_name}/logs/error.log
#     CustomLog /home/{website.ftp_username}/{subdomain_full_name}/logs/access.log combined
#     <FilesMatch \.php$>
#         SetHandler "proxy:unix:/run/php/php{php_version}-fpm.sock|fcgi://localhost"
#     </FilesMatch>
# </VirtualHost>
#             """
#             with open(apache_conf, 'w') as f:
#                 f.write(apache_config_content)
#             subprocess.run(['sudo', 'chown', 'root:root', apache_conf], check=True)

#             # Generate FTP credentials
#             subdomain_ftpuser = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
#             subdomain_ftppass = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
            
#             # FTP user creation
#             subprocess.run(['sudo', 'useradd', '-m', '-s', '/bin/false', subdomain_ftpuser], check=True)
#             subprocess.run(['sudo', 'bash', '-c', f'echo "{subdomain_ftpuser}:{subdomain_ftppass}" | sudo chpasswd'], check=True)

#             # Vsftpd user configuration
#             vsftpd_user_conf = f"/etc/vsftpd/user_conf/{subdomain_ftpuser}.conf"
#             vsftpd_config_content = f"""
# local_root=/home/{website.ftp_username}/{website.website_name}/{subdomain_full_name}
# write_enable=YES    
# local_umask=022
# file_open_mode=0755
#             """
            
#             with open(vsftpd_user_conf, 'w') as conf_file:
#                 conf_file.write(vsftpd_config_content)
            
#             subprocess.run(['sudo', 'chown', 'root:root', vsftpd_user_conf], check=True)

#             # Set permissions for subdomain
#             subprocess.run(['sudo', 'chmod', '-R', '775', f'/home/{website.ftp_username}/{subdomain_full_name}'], check=True)
#             subprocess.run(['sudo', 'chown', '-R', f'{subdomain_ftpuser}:{website.ftp_username}', f'/home/{website.ftp_username}/{subdomain_full_name}'], check=True)

#             # Install and configure PHP
#             install_php_and_configure(website.ftp_username, website.website_name, subdomain_name, php_version)

#             # Enable site and reload Apache
#             subprocess.run(['sudo', 'a2ensite', f'{subdomain_full_name}.conf'], check=True)
#             subprocess.run(['sudo', 'systemctl', 'reload', 'apache2'], check=True)

#             # Ensure you have the customer instance (adjust as necessary)
#             customer_instance = website.customer  # This gets the customer associated with the website

#             # Save the website instance to the database
#             website = Website(
#                 customer=customer_instance,
#                 website_name=subdomain_full_name,
#                 ftp_username=subdomain_ftpuser,
#                 ftp_password=subdomain_ftppass,
#                 php_version=php_version,
#                 database_allowed=1  # Set to your desired value
#             )
#             website.save()

#             subdomain = Subdomain(
#                 website=website,
#                 subdomain_name=subdomain_full_name,
#                 php_version=php_version,
#                 subdomainftpuser=subdomain_ftpuser,
#                 subdomainftppass=subdomain_ftppass
#             )
#             subdomain.save()

#             messages.success(request, f'Subdomain created successfully. FTP Username: {subdomain_ftpuser}, Password: {subdomain_ftppass}')
#             return redirect('add_subdomain', website_id=website_id)

#         except subprocess.CalledProcessError as e:
#             messages.error(request, f'Error while creating subdomain: Command failed with return code {e.returncode}.')
#         except Exception as e:
#             messages.error(request, f'Error while creating subdomain: {str(e)}')
        
#         return redirect('website_info', id=website_id)
    
#     php_versions = ['7.4', '8.0', '8.1']  # Available PHP versions
#     return render(request, 'user/add_subdomain.html', {'website': website, 'php_versions': php_versions})


# @login_required
# def add_subdomain(request, website_id):
#     # Fetch the existing website by its ID
#     website = get_object_or_404(Website, id=website_id)
    
#     if request.method == 'POST':
#         subdomain_name = request.POST.get('subdomain_name')
#         php_version = request.POST.get('php_version')
        
#         # Validate input
#         if not subdomain_name:
#             messages.error(request, 'Please provide a subdomain name.')
#             return redirect('add_subdomain', website_id=website_id)

#         # Add logic to create subdomain directories and configure DNS, Apache, etc.
#         try:
#             subdomain_full_name = f"{subdomain_name}.{website.website_name}"
#             ftp_username = website.ftp_username  # Using the same FTP username as the main domain
            
#             # Create subdomain directory
#             subprocess.run(['sudo', 'mkdir', '-p', f'/home/{ftp_username}/{subdomain_full_name}/public_html', f'/home/{ftp_username}/{subdomain_full_name}/logs'], check=True)
            
#             # Set permissions for subdomain
#             subprocess.run(['sudo', 'chown', '-R', f'{ftp_username}:{ftp_username}', f'/home/{ftp_username}/{subdomain_full_name}'], check=True)
#             subprocess.run(['sudo', 'chmod', '-R', '755', f'/home/{ftp_username}/{subdomain_full_name}'], check=True)

#             # DNS resolution for subdomain
#             subprocess.run(f'sudo sh -c "echo \'192.168.3.239    {subdomain_full_name}\' >> /etc/hosts"', shell=True, check=True)

#             # Create Apache config for subdomain
#             apache_conf = f"/etc/apache2/sites-available/{subdomain_full_name}.conf"
#             apache_config_content = f"""
# <VirtualHost *:80>
#     ServerAdmin webmaster@{subdomain_full_name}
#     ServerName {subdomain_full_name}
#     DocumentRoot /home/{ftp_username}/{subdomain_full_name}/public_html/
#     <Directory /home/{ftp_username}/{subdomain_full_name}/public_html/>
#         AllowOverride all
#         Require all granted
#         Options FollowSymlinks
#         DirectoryIndex home.html
#         Allow from all
#     </Directory>
#     ErrorLog /home/{ftp_username}/{subdomain_full_name}/logs/error.log
#     CustomLog /home/{ftp_username}/{subdomain_full_name}/logs/access.log combined
#     <FilesMatch \.php$>
#         SetHandler "proxy:unix:/run/php/php{php_version}-fpm-{ftp_username}-{subdomain_full_name}.sock|fcgi://localhost"
#     </FilesMatch>
# </VirtualHost>
#             """
#             with open(apache_conf, 'w') as f:
#                 f.write(apache_config_content)

#             subprocess.run(['sudo', 'chown', 'root:root', apache_conf], check=True)
#             subprocess.run(['sudo', 'a2ensite', f'{subdomain_full_name}.conf'], check=True)
            
#             subprocess.run(['sudo', 'systemctl', 'reload', 'apache2'], check=True)
#             subprocess.run(['sudo', 'systemctl', 'reload', f'php{php_version}-fpm'], check=True)
#             subprocess.run(['sudo', 'systemctl', 'restart', f'php{php_version}-fpm'], check=True)

#             install_php_and_configure(ftp_username, website.website_name, subdomain_name=subdomain_name, php_version=php_version)
            
#             subdomain = Subdomain(
#                 website=website,
#                 subdomain_name=subdomain_full_name,
#                 php_version=php_version
#             )
#             subdomain.save()

#             messages.success(request, 'Subdomain created successfully.')
#             return redirect('website_info', website_id=website_id)
        
#         except Exception as e:
#             messages.error(request, f'Error while creating subdomain: {str(e)}')
#             return redirect('add_subdomain', website_id=website_id)

#     php_versions = ['7.4', '8.0', '8.1']  # Example PHP versions
#     return render(request, 'user/add_subdomain.html', {'website': website, 'php_versions': php_versions})




@login_required
def add_website(request):
    customers = Customer.objects.all()
    user_id = request.user.id

    if request.method == 'POST':
        customer_email = request.POST.get('customer_email')
        website_name = request.POST.get('website_name')
        ftp_username = request.POST.get('ftp_username')
        ftp_password = request.POST.get('ftp_password')
        ftp_confirm_password = request.POST.get('ftp_confirm_password')
        php_version = request.POST.get('php_version')
        database_allowed = request.POST.get('database_allowed')
        subdomain_name = request.POST.get('subdomain_name')


        if not (customer_email and website_name and ftp_username and ftp_password and ftp_confirm_password and php_version and database_allowed):
            messages.error(request, 'Please fill out all required fields')
            return redirect('add_website')

        if not (website_name.endswith('.com') or website_name.endswith('.in')):
            messages.error(request, 'Website name must end with .com or .in')
            return redirect('add_website')

        if ftp_password != ftp_confirm_password:
            messages.error(request, 'FTP passwords do not match')
            return redirect('add_website')

        try:
            create_user_command = ['sudo', 'useradd', ftp_username]
            subprocess.run(create_user_command, check=True)

            create_dirs_command = ['sudo', 'mkdir', '-p', f'/home/{ftp_username}/{website_name}/public_html', f'/home/{ftp_username}/{website_name}/logs']
            subprocess.run(create_dirs_command, check=True)

            index_file_path = f'/home/{ftp_username}/{website_name}/public_html/index.html'
            touch_index_file_command = ['sudo', 'touch', index_file_path]
            subprocess.run(touch_index_file_command, check=True)

            # Change ownership to root:root
            chown_command = ['sudo', 'chown', 'root:root', index_file_path]
            subprocess.run(chown_command, check=True)


            set_permissions_command = ['sudo', 'chown', '-R', f'{ftp_username}:{ftp_username}', f'/home/{ftp_username}', f'/home/{ftp_username}/{website_name}']
            subprocess.run(set_permissions_command, check=True)
            subprocess.run(['sudo', 'chmod', '-R', '755', f'/home/{ftp_username}/{website_name}'], check=True)

            subprocess.run(['sudo', '-u', ftp_username, 'touch', f'/home/{ftp_username}/{website_name}/logs/error.log', f'/home/{ftp_username}/{website_name}/logs/access.log'], check=True)
            
            create_ftp_user(ftp_username, ftp_password)

           
            if subdomain_name:
                install_php_and_configure(ftp_username, website_name, subdomain_name=subdomain_name, php_version=php_version)
            else:
                install_php_and_configure(ftp_username, website_name, php_version=php_version)
            
            create_database_and_user(ftp_username, website_name)


            subprocess.run(f'sudo sh -c "echo \'192.168.3.239    {website_name}\' >> \'/etc/hosts\'"', shell=True, check=True)
            print(f"DNS resolution set up for domain {website_name}.")

            apache_conf = f"/etc/apache2/sites-available/{website_name}.conf"
            apache_config_content = f"""
<VirtualHost *:80>
    ServerName {website_name}
    ServerAlias www.{website_name}
    DocumentRoot /home/{ftp_username}/{website_name}/public_html
    ErrorLog /home/{ftp_username}/{website_name}/logs/error.log
    CustomLog /home/{ftp_username}/{website_name}/logs/access.log combined

    <Directory /home/{ftp_username}/{website_name}/public_html>
        Options -FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    # PHP-FPM Configuration
    <FilesMatch \.php$>
        SetHandler "proxy:unix:/run/php/php{php_version}-fpm-{ftp_username}.sock|fcgi://localhost/"
    </FilesMatch>
</VirtualHost>
            """
            with open(apache_conf, 'w') as f:
                f.write(apache_config_content)

            subprocess.run(['sudo', 'chown', 'root:root', apache_conf], check=True)

            subprocess.run(['sudo', 'a2ensite', f'{website_name}.conf'], check=True)

            subprocess.run(['sudo', 'systemctl', 'reload', f'php{php_version}-fpm'], check=True)
            subprocess.run(['sudo', 'systemctl', 'restart', f'php{php_version}-fpm'], check=True)

            customer = Customer.objects.get(email=customer_email)
        except Customer.DoesNotExist:
            messages.error(request, 'Customer not found')
            return redirect('add_website')
        except subprocess.CalledProcessError as e:
            error_message = e.stderr.decode() if e.stderr else str(e)
            messages.error(request, f'Error: {error_message}')
            return redirect('add_website')
        except Exception as e:
            messages.error(request, f'Unexpected error: {str(e)}')
            return redirect('add_website')
        
        website = Website(
            customer=customer,
            website_name=website_name,
            ftp_username=ftp_username,
            ftp_password=ftp_password,
            php_version=php_version,
            database_allowed=database_allowed
        )
        website.save()
        
        messages.success(request, 'Website added successfully')
        return redirect('add_website')

    php_versions = ['7.4', '8.0', '8.1']  
    return render(request, 'user/add_website.html', {'customers': customers, 'php_versions': php_versions, 'user_id': user_id})

# @csrf_protect
# @login_required
# def add_website(request):
#     customers = Customer.objects.all()
#     user_id = request.user.id
#     if request.method == 'POST':
#         customer_email = request.POST.get('customer_email')
#         website_name = request.POST.get('website_name')
#         ftp_username = request.POST.get('ftp_username')
#         ftp_password = request.POST.get('ftp_password')
#         ftp_confirm_password = request.POST.get('ftp_confirm_password')
#         php_version = request.POST.get('php_version')
#         database_allowed = request.POST.get('database_allowed')

#         # Validate the form data
#         if not (customer_email and website_name and ftp_username and ftp_password and ftp_confirm_password and php_version and database_allowed):
#             messages.error(request, 'Please fill out all required fields')
#             return redirect('add_website')

#         if not (website_name.endswith('.com') or website_name.endswith('.in')):
#             messages.error(request, 'Website name must end with .com or .in')
#             return redirect('add_website')

#         if ftp_password != ftp_confirm_password:
#             messages.error(request, 'FTP passwords do not match')
#             return redirect('add_website')

#         try:
#             # Create user without home directory
#             create_user_command = ['sudo', 'useradd', ftp_username]
#             subprocess.run(create_user_command, check=True)

#             create_ftp_user(ftp_username, ftp_password)

#             # Create necessary directories with sudo
#             create_dirs_command = ['sudo',  '-u', 'root','mkdir', '-p', f'/home/{ftp_username}/{website_name}/public_html', f'/home/{ftp_username}/{website_name}/logs']
#             subprocess.run(create_dirs_command, check=True)

#             # Set permissions for directories and files
#             set_permissions_command = ['sudo', 'chown', '-R', f'{ftp_username}:{ftp_username}', f'/home/{ftp_username}', f'/home/{ftp_username}/{website_name}']
#             subprocess.run(set_permissions_command, check=True)
#             subprocess.run(['sudo', 'chmod', '-R', '755', f'/home/{ftp_username}/{website_name}'], check=True)

#             # Create logs files
#             subprocess.run(['sudo', '-u', ftp_username, 'touch', f'/home/{ftp_username}/{website_name}/logs/error.log', f'/home/{ftp_username}/{website_name}/logs/access.log'], check=True)

#             # Create index.html file using touch command
#             # subprocess.run(['sudo', '-u', ftp_username, 'touch', f'/home/{ftp_username}/{website_name}/public_html/home.html'], check=True)

#             # Set permissions for index.html
#             # subprocess.run(['sudo', 'chmod', '755', f'/home/{ftp_username}/{website_name}/public_html/home.html'], check=True)

#             # Modify user's shell configuration file to change directory upon login
#             subprocess.run(f'sudo sh -c "echo \'cd /home/{ftp_username}/{website_name}\' >> \'/home/{ftp_username}/.bashrc\'"', shell=True, check=True)

#             # Set up DNS resolution locally
            # subprocess.run(f'sudo sh -c "echo \'192.168.3.239    {website_name}\' >> \'/etc/hosts\'"', shell=True, check=True)
            # print(f"DNS resolution set up for domain {website_name}.")

#             # Create Apache virtual host configuration
#             apache_conf = f"/etc/apache2/sites-available/{website_name}.conf"
#             apache_config_content = f"""
# <VirtualHost *:80>
#     ServerAdmin webmaster@{website_name}
#     ServerName {website_name}
#     DocumentRoot /home/{ftp_username}/{website_name}/public_html/
#     <Directory /home/{ftp_username}/{website_name}/public_html/>
#         AllowOverride all
#         Require all granted
#         Options FollowSymlinks
#         DirectoryIndex home.html 
#         Allow from all
#     </Directory>
#     ErrorLog /home/{ftp_username}/{website_name}/logs/error.log
#     CustomLog /home/{ftp_username}/{website_name}/logs/access.log combined
# </VirtualHost>
#             """

#             subprocess.run(f'sudo sh -c "echo \'{apache_config_content}\' > {apache_conf}"', shell=True, check=True)

#             print(f"Apache virtual host configuration created: {apache_conf}")

#             # Enable Apache site configuration
#             enable_site_command = ['sudo', 'a2ensite', f'{website_name}.conf']
#             subprocess.run(enable_site_command, check=True)
#             print(f"Enabled Apache site configuration for {website_name}")

#             # Reload Apache
#             subprocess.run(['sudo', 'systemctl', 'reload', 'apache2'], check=True)
#             print("Apache reloaded successfully.")

#             customer = Customer.objects.get(email=customer_email)
#         except Customer.DoesNotExist:
#             messages.error(request, 'Customer not found')
#             return redirect('add_website')
#         except subprocess.CalledProcessError as e:
#             error_message = e.stderr.decode() if e.stderr else str(e)
#             messages.error(request, f'Error: {error_message}')
#             return redirect('add_website')
#         except Exception as e:
#             messages.error(request, f'Unexpected error: {str(e)}')
#             return redirect('add_website')

#         # Save data to the database
#         website = Website(
#             customer=customer,
#             website_name=website_name,
#             ftp_username=ftp_username,
#             ftp_password=ftp_password,
#             php_version=php_version,
#             database_allowed=database_allowed
#         )
#         website.save()

#         messages.success(request, 'Website added successfully')
#         return redirect('add_website')

#     customers = Customer.objects.all()
#     php_versions = ['7.4', '8.0', '8.1']  # Example PHP versions, you can fetch this from your model or config
#     return render(request, 'user/add_website.html', {'customers': customers, 'php_versions': php_versions , 'user_id': user_id})



# from django.contrib.auth import authenticate, login
# from django.shortcuts import render, redirect
# from django.contrib import messages
# from popo.models import User, Customer
# from popo.auth_backends import CustomBackend, CustomerBackend

# def login_view(request):
#     if request.method == 'POST':
#         username = request.POST['username']
#         password = request.POST['password']

#         print(f"Username: {username}")
#         print(f"Entered Password: {password}")

#         # First, attempt to authenticate as an admin user
#         user = CustomBackend().authenticate(request, username=username, password=password)

#         if user is not None:
#             print("Admin password match found, logging in user.")
#             login(request, user, backend='popo.auth_backends.CustomBackend')  # Specify the backend
            
#             # Print user details to the terminal
#             print(f"Authenticated User: {user.username}")
#             print(f"User Email: {user.emailid}")
#             print(f"User is Active: {user.is_active}")
#             print(f"User is Admin: {user.is_admin}")

#             return redirect('home')  # Redirect to the home page after successful login
        
#         else:
#             # If admin login fails, check for customer login
#             customer = CustomerBackend().authenticate(request, username=username, password=password)
#             if customer is not None:
#                 print("Customer login successful.")
                
#                 # Manually log the customer in by setting the session
#                 request.session['customer_id'] = customer.id
#                 request.session['customer_email'] = customer.email
#                 request.session.modified = True
#                 print(f"Session Data: {request.session.items()}")
                
#                 # Try redirecting to a different page first
#                 return redirect('userhome')
#             else:
#                 print("Password mismatch or user does not exist.")
#                 messages.error(request, 'Invalid username or password')

#     return render(request, 'user/index.html')



# def logout_view(request):
#     # Get the current user's ID
#     user_id = request.user.id

#     # Print user_id for debugging
#     print(f"User ID: {user_id}")

#     # Invalidate all sessions for the user
#     sessions = Session.objects.filter(expire_date__gte=timezone.now())
#     print(sessions)
#     for session in sessions:
#         data = session.get_decoded()
#         print(data)
#         if data.get('_auth_user_id') == str(user_id):
#             session.delete()

#     # Log out the user
#     logout(request)
#     return redirect('index')



from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.sessions.models import Session
from django.utils import timezone
from popo.models import User, Customer
from popo.auth_backends import CustomBackend, CustomerBackend

from django.utils.cache import add_never_cache_headers

def login_view(request):
    
    if request.user.is_authenticated:
        print("User is already authenticated, redirecting to home page.")
        return redirect('home') 

    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        print(f"Username: {username}")
        print(f"Entered Password: {password}")

        
        user = CustomBackend().authenticate(request, username=username, password=password)

        if user is not None:
            print("Admin password match found, logging in user.")
            login(request, user, backend='popo.auth_backends.CustomBackend')  # Specify the backend

            # Print user details to the terminal
            print(f"Authenticated User: {user.username}")
            print(f"User Email: {user.emailid}")
            print(f"User is Active: {user.is_active}")
            print(f"User is Admin: {user.is_admin}")

            return redirect('home')  
        
        else:
            # If admin login fails, check for customer login
            customer = CustomerBackend().authenticate(request, username=username, password=password)
            if customer is not None:
                print("Customer login successful.")

                # Manually log the customer in by setting the session
                request.session['customer_id'] = customer.id
                request.session['customer_email'] = customer.email
                request.session.modified = True
                print(f"Session Data: {request.session.items()}")

                # Redirect to the user home page
                return redirect('userhome')
            else:
                print("Password mismatch or user does not exist.")
                messages.error(request, 'Invalid username or password')

    # Prevent browser from caching the login page
    response = render(request, 'user/index.html')
    add_never_cache_headers(response)  # Prevent caching
    return response


def logout_view(request):
    # Get the current user's ID
    user_id = request.user.id

    # Print user_id for debugging
    print(f"User ID: {user_id}")

    # Invalidate all sessions for the user
    sessions = Session.objects.filter(expire_date__gte=timezone.now())
    print(sessions)
    for session in sessions:
        data = session.get_decoded()
        print(data)
        if data.get('_auth_user_id') == str(user_id):
            session.delete()

    # Log out the user
    logout(request)
    return redirect('index')

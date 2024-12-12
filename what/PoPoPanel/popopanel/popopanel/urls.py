"""
This file is part of POPOPANEL.

@package     POPOPANEL is part of WHAT PANEL – Web Hosting Application Terminal Panel.
@copyright   2023-2024 Version Next Technologies and MadPopo. All rights reserved.
@license     BSL; see LICENSE.txt
@link        https://www.version-next.com
"""
from django.contrib import admin
from django.urls import path, include
from popo import views   

urlpatterns = [
    path('admin/', admin.site.urls),
    path('home/', views.HomePage, name='home'),  
    path('userhome/', views.userhome, name='userhome'),
    path('', views.login_view, name='index'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('add_customer/', views.add_customer, name='add_customer'),
    path('add_website/', views.add_website, name='add_website'),
    path('list_websites/', views.list_websites, name='list_websites'),
    path('list_customers/', views.list_customers, name='list_customers'),
    path('website/<int:id>/', views.website_info, name='website_info'),
    path('subdomain/<int:id>/', views.subdomain_info, name='subdomain_info'),
    path('customer_detail/<int:customer_id>/', views.customer_detail, name='customer_detail'),
    path('update_hosts_file/', views.update_hosts_file, name='update_hosts_file'),
    path('update_website/<int:website_id>/', views.update_website, name='update_website'),
    path('delete_website/<int:website_id>/', views.delete_website, name='delete_website'),
    path('ftp-users/<int:website_id>/', views.ftp_users, name='ftp_users'),
    path('ftp_users/<int:domain_id>/<str:domain_type>/', views.ftp_users, name='ftp_users'),
    path('create_ftp_user/', views.create_ftp_user, name='create_ftp_user'),
    path('update_ftp_details/<int:website_id>/', views.update_ftp_user, name='update_ftp_details'),
    path('file_manager/<int:website_id>/', views.file_manager, name='file_manager'),
    path('website/<int:website_id>/additional_ftp/', views.additional_ftp, name='additional_ftp'),
    path('update_php_version/<int:website_id>/', views.update_php_version, name='update_php_version'),
    path('website/<int:website_id>/add-database/', views.add_database, name='add_database'),
    path('website/<int:website_id>/databases/', views.list_databases, name='list_databases'),
    path('redirect-to-phpmyadmin/', views.redirect_to_phpmyadmin, name='redirect_to_phpmyadmin'),
    path('website/<int:website_id>/database/<int:database_id>/remove/', views.remove_database, name='remove_database'),
    path('website/<int:website_id>/add_subdomain/', views.add_subdomain, name='add_subdomain'),
    path('wordpress_user/<int:website_id>/', views.wordpress_user, name='wordpress_user'),
    # path('wordpress/<int:website_id>/', views.wordpress, name='wordpress'),
    path('install_wordpress/<int:website_id>/', views.install_wordpress, name='install_wordpress'),
    path('wp_auto_login/<int:website_id>/', views.wp_auto_login, name='wp_auto_login'),
    path('generate_wp_credentials/<int:website_id>/', views.generate_wp_credentials, name='generate_wp_credentials'),
    path('upload_file/<int:website_id>/', views.upload_file, name='upload_file'),
    path('list_plugins/<int:website_id>/', views.list_plugins, name='list_plugins'),
    path('search-plugin/<int:website_id>/', views.search_plugin, name='search_plugin'),
    path('install-plugin/<int:website_id>/', views.install_plugin, name='install_plugin'),
    path('search-themes/<int:website_id>/', views.search_themes, name='search_themes'),
    path('install-theme/<int:website_id>/', views.install_theme, name='install_theme'),  
    path('toggle_plugin/<int:website_id>/', views.toggle_plugin, name='toggle_plugin'),
    path('upload-theme/<int:website_id>/', views.upload_theme, name='upload_theme'),
    path('list-themes/<int:website_id>/', views.list_themes, name='list_themes'),
    path('ssl_page/<int:website_id>/', views.ssl_page, name='ssl_page'),
    path('setup-domain/', views.setup_domain, name='setup_domain'),
    path('remove_website/', views.remove_website, name='remove_website'),
    path('delete_website_action/<int:website_id>/', views.delete_website_action, name='delete_website_action'),
    path('subdomains/<int:website_id>/', views.list_subdomain, name='list_subdomain'),
    path('log/<int:website_id>/', views.logs, name='logs'),
    path('logs/<int:website_id>/access/', views.view_access_logs, name='logs_access'),
    path('logs/<int:website_id>/error/', views.view_error_logs, name='logs_error'),
    path('remove-subdomain/<int:subdomain_id>/', views.remove_subdomain, name='remove_subdomain'),
    path('uninstall-wordpress/<int:website_id>/', views.uninstall_wordpress, name='uninstall_wordpress'),
    # path('toggle-theme/', views.toggle_theme, name='toggle_theme'),
    ]

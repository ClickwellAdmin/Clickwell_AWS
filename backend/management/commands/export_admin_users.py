# yourapp/management/commands/export_admin_users.py

import xlwt
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User

class Command(BaseCommand):
    help = 'Export a list of admin users to an XLS file'

    def handle(self, *args, **kwargs):
        # Query all admin users (both staff and superusers)
        admin_users = User.objects.filter(is_staff=True)

        # Create a new Excel workbook and add a sheet
        workbook = xlwt.Workbook()
        sheet = workbook.add_sheet('Admin Users')

        # Define headers
        headers = ['Username', 'First Name', 'Last Name', 'Email']

        # Write headers to the first row
        for col_num, header in enumerate(headers):
            sheet.write(0, col_num, header)

        # Write admin user data
        row_num = 1
        for user in admin_users:
            sheet.write(row_num, 0, user.username)
            sheet.write(row_num, 1, user.first_name)
            sheet.write(row_num, 2, user.last_name)
            sheet.write(row_num, 3, user.email)

            row_num += 1

        # Save the workbook to a file
        workbook.save('admin_users.xls')

        self.stdout.write(self.style.SUCCESS('Admin users exported to admin_users.xls'))

import win32com.client
from pywintypes import com_error


# Path to original excel file
WB_PATH = r'C:\Users\plair\OneDrive\Documents\PROGRAM\work\ปีสี่\projectT2(edit)V6\excel\result01.xls'
# PDF path when saving
PATH_TO_PDF = r'C:\Users\plair\OneDrive\Documents\PROGRAM\work\ปีสี่\projectT2(edit)V6\pdf\pdf02.pdf'


excel = win32com.client.Dispatch("Excel.Application")

excel.Visible = False

try:
    print('Start conversion to PDF')

    # Open
    wb = excel.Workbooks.Open(WB_PATH)

    # Specify the sheet you want to save by index. 1 is the first (leftmost) sheet.
    work_sheets = wb.Worksheets[0]

    # Save
    wb.ActiveSheet.ExportAsFixedFormat(0, PATH_TO_PDF)
except com_error as e:
    print('failed.')
else:
    print('Succeeded.')
finally:
    wb.Close()
    excel.Quit()

import xlwt
from xlwt import Workbook

wb = Workbook()

sheet1 = wb.add_sheet('Sheet 1')
#sheet1.write(row,col, data, style)
sheet1.write(1, 0, '1st ')
sheet1.write(2, 0, '2nd Data')
sheet1.write(3, 0, '3rd ')
sheet1.write(4, 0, '4th Data')

wb.save('sample_data2.xls')

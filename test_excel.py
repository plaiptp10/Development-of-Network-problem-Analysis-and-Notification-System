import pandas as pd

list_delay = [1, 3, 1, 2, 2, 6, 8, 5, 4, 3, 7, 5]
avg_lost = 0
col_delay = "Delay"
col_lost = "Lost"
for i in range(10):
    avg_lost += 1

data = pd.DataFrame({col_delay: list_delay, col_lost: avg_lost})
data.to_excel('test_excel.xlsx', sheet_name='sheet1', index=False)

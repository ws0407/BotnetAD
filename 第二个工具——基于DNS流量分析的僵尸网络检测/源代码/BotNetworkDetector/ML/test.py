import pandas as pd
from pandas import read_csv

data = read_csv('test.csv')

data['RESULT'] = [1,0,0,0,1,1,1,1]
data.to_csv('test.csv')

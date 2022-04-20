import datetime, subprocess, os.path
from IPInfo import IPDetails
import csv, matplotlib.pyplot as plt
from MachineLearning import BotNetDetector
import pandas as pd

fn_in = "../Output/DNS_FP.csv"

df = pd.read_csv(fn_in, low_memory=False)

print df.shape[0]

df.close()

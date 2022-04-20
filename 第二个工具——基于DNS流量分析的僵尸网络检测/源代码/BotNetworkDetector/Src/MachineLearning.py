# -*- coding: utf-8 -*-

# BotDAD Machine Learning Module

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import confusion_matrix
import itertools
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from matplotlib.colors import LinearSegmentedColormap
import matplotlib.lines as mlines
from sklearn.metrics import accuracy_score
import cPickle


class BotNetDetector:

    def __init__(self):
        self.df = ""
        self._df_ = ""

    # 读取csv文件，保存到self.df里
    def import_db(self, filename):
        # from imblearn.over_sampling import SMOTE

        # 设置主题风格
        sns.set_style("darkgrid")
        plt.style.use("seaborn-poster")

        # % matplotlib
        # inline
        # 加载数据集
        self.df = pd.read_csv("export.csv", low_memory=False)

        print("训练集中一共有%s行，%s 列" % self.df.shape)

        self._df_ = pd.read_csv(filename, low_memory=False)

        print("测试集中一共有%s行，%s 列" % self._df_.shape)

        # df1 = pd.read_table("export.csv",nrows=10) #只读取前面10行
        # print(df1)
        # print("\n\n123\n\n")
        # print(self.df.head()) # 输出表头
        # 输出前6行
        print(self.df[:6])

    # y：结果，clean or Bot -> 1 or 0
    def encode_values(self):
        self.y = self.df.Result.str.strip()

        self.labelencoder_y = LabelEncoder()

        self.y = self.labelencoder_y.fit_transform(self.y)

    # 统计clean Bot分别有多少
    def display_count(self):
        # optional
        clean = 0
        Bot = 0
        for row_index, row in self.df.iterrows():
            if (row.Result.strip()) == 'Clean':
                clean = clean + 1
            else:
                # print (row)
                Bot = Bot + 1
        print(clean, Bot)

    # 数据分类，0.3的测试集
    def split_data(self):
        self.df.Result.unique()

        # P1-P15，得到除了Result以外的所有变量
        self.x = self.df[self.df.columns.difference(['Result'])].values
        self.x_test = self._df_[self._df_.columns.difference(['Hostname'])].values

        print(self.x_test[:5])

        print("自变量X的数目和维度:  %s, %s" % self.x.shape)
        print("因变量Y的数目和维度:  %s, 1" % self.y.shape)

    # 随机森林算法
    def create_forest(self):
        self.rf_classifier = RandomForestClassifier(n_estimators=10, max_depth=None, min_samples_split=2,
                                                    random_state=0)
        self.rf_classifier.fit(self.x, self.y)
        print("[随机森林算法]训练集分数：%s" % self.rf_classifier.score(self.x, self.y))

    # 每个特征值的importance，权重
    def show_feature_imp(self):
        self.param_array = [
            ['P1', 'Nbr. of DNS requests per hour ', 7500],
            ['P2', 'Nbr. of Distinct DNS requests ', 1500],
            ['P3', 'Highest Nbr. of requests(single domain)', 1000],
            ['P4', 'Average Nbr. of requests ', 300],
            ['P5', 'Highest Nbr. of requests ', 500],
            ['P6', 'Nbr. of MX Record Queries ', 10],
            ['P7', 'Nbr. of PTR Record Queries ', 500],
            ['P8', 'Nbr. of Distinct DNS Servers ', 5],
            ['P9', 'Nbr. of Distinct TLD  Queried ', 25],
            ['P10', 'Nbr. of Distinct SLD  Queried ', 500],
            ['P11', 'Uniqueness ratio ', 500],
            ['P12', 'Nbr. of Failed Queries', 12],
            ['P13', 'Nbr. of Distinct Cities', 70],
            ['P14', 'Nbr. of Distinct Countries ', 30],
            ['P15', 'Flux ratio per hour ', 100]]

        self.importances = self.rf_classifier.feature_importances_
        std = np.std([self.rf_classifier.feature_importances_ for tree in self.rf_classifier.estimators_],
                     axis=0)
        indices = np.argsort(self.importances)[::-1]

        # Print the feature ranking
        print("排名\t|\t特征值\t|\t\t\t\t\t重要性")

        for f in range(self.x.shape[1]):
            print("%2d. %-40s %5s (%f)" % (
            f + 1, self.param_array[indices[f]][1], "(P" + str(indices[f] + 1) + ")", self.importances[indices[f]]))

    def predicted_result(self, filename):
        # Predicted Model
        self.y_pred = self.rf_classifier.predict(self.x_test)
        print (self.y_pred)
        result = []
        for item in self.y_pred:
            if item == 1:
                result.append("clean")
            else:
                result.append("Bot")
        self._df_["RESULT"] = result
        self._df_.to_csv(filename)

    def feature_plot(self):
        self.feature_x = self.df.loc[:, 'P1':'P15'].values
        self.feature_y = self.df.Result.str.strip()

        # print("feature_plot")
        # print(self.feature_x[:5, 1])
        # print(self.feature_x[1, :5])
        # print(self.feature_y[:5])
        # print("feature_plot")

        from sklearn.preprocessing import LabelEncoder, OneHotEncoder
        labelencoder_y = LabelEncoder()

        self.feature_y = self.labelencoder_y.fit_transform(self.feature_y)

        self.feature_param_array = [
            ['P1', 'Nbr. of DNS requests per hour ', 7500],
            ['P2', 'Nbr. of Distinct DNS requests ', 1500],
            ['P3', 'Highest Nbr. of requests(single domain)', 1000],
            ['P4', 'Average Nbr. of requests ', 300],
            ['P5', 'Highest Nbr. of requests ', 500],
            ['P6', 'Nbr. of MX Record Queries ', 10],
            ['P7', 'Nbr. of PTR Record Queries ', 500],
            ['P8', 'Nbr. of Distinct DNS Servers ', 5],
            ['P9', 'Nbr. of Distinct TLD  Queried ', 25],
            ['P10', 'Nbr. of Distinct SLD  Queried ', 500],
            ['P11', 'Uniqueness ratio ', 500],
            ['P12', 'Nbr. of Failed Queries', 12],
            ['P13', 'Nbr. of Distinct Cities', 70],
            ['P14', 'Nbr. of Distinct Countries ', 30],
            ['P15', 'Flux ratio per hour ', 100]]

        print("\tMax\t\t|\t\tMin\t\t|\t\tAverage")
        # 就是range 0-14
        for i in np.arange(15):
            print("%-20s%-15s%-s" % (str(max(self.feature_x[:, i])) ,str(min(self.feature_x[:, i])) ,str(np.mean(self.feature_x[:, i]))))

        # plt.subplot(2,2,1)
        fig = plt.gcf()
        fig.set_size_inches(5, 4)
        # plt.subplots_adjust(left=0.52, bottom=0.08, right=0.85, top=0.92, wspace=0.01, hspace=0.08)

        #for i in np.arange(15):
         #   self.feature_plot_array(self.feature_x[:, i], i, self.feature_param_array[i][2])

        # plt.show

    def save_model(self):
        with open('model', 'wb') as f:
            cPickle.dump(self.rf_classifier, f)

    def load_model(self):
        with open('model', 'rb') as f:
            self._rf_classifier = cPickle.load(f)

    def get_x_data(self, filename):
        self._df_ = pd.read_csv(filename, low_memory=False)
        # print("测试集中一共有%s行，%s 列" % self._df_.shape)
        self.x_value = self._df_[self._df_.columns.difference(['Hostname'])].values

    def get_y_data(self, filename):
        self.y_value = self._rf_classifier.predict(self.x_value)
        result = []
        for item in self.y_value:
            if item == 1:
                result.append("clean")
            else:
                result.append("Bot")
        self._df_["RESULT"] = result
        self._df_.to_csv(filename)


if __name__ == '__main__':
    
    fn_in = "../Output/DNS_FP.csv"
    fn_out = "../Output/DNS_FP_RESULT.csv"
    obj = BotNetDetector()

    obj.load_model()
    obj.get_x_data(fn_in)
    obj.get_y_data(fn_out)
    print("end")


"""
    obj.import_db(fn_in)

    obj.encode_values()
    obj.display_count()
    obj.split_data()

    obj.feature_plot()

    obj.create_forest()
    obj.show_feature_imp()
    obj.predicted_result(fn_out)
"""




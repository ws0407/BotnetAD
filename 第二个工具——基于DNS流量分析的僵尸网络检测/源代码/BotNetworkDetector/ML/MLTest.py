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


class BotDAD:

    def __init__(self):
        self.df = ""

    # 读取csv文件，保存到self.df里
    def import_db(self):
        # from imblearn.over_sampling import SMOTE

        # 设置主题风格
        sns.set_style("darkgrid")
        plt.style.use("seaborn-poster")

        # % matplotlib
        # inline
        # 加载数据集
        self.df = pd.read_csv("export.csv", low_memory=False)

        print("数据集中一共有%s行，%s 列" % self.df.shape)

        # df1 = pd.read_table("export.csv",nrows=10) #只读取前面10行
        # print(df1)
        # print("\n\n123\n\n")
        # print(self.df.head()) # 输出表头
        # 输出前6行
        # print(self.df[:6])

    # y：结果，clean or Bot -> 1 or 0
    def encode_values(self):
        self.y = self.df.Result.str.strip()

        # print("\nencode_values\n")
        # print(self.y[:5])
        # print("\nencode_values\n")

        self.labelencoder_y = LabelEncoder()

        self.y = self.labelencoder_y.fit_transform(self.y)

    # 统计clean Bot分别有多少
    def display_count(self):
        # optional
        clean = 0
        Bot = 0
        for row_index, row in self.df.iterrows():
            if ((row.Result.strip()) == 'Clean'):
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

        print("自变量X的数目和维度:  %s, %s" % self.x.shape)
        print("因变量Y的数目和维度:  %s, 1" % self.y.shape)

        from sklearn.model_selection import train_test_split
        self.x_train, self.x_test, self.y_train, self.y_test = train_test_split(self.x, self.y, test_size=0.3,
                                                                                random_state=42)

    # 随机森林算法
    def create_forest(self):
        # Random forest
        # 参数：
        # n_estimators:integer,optional(default=10)   森林里（决策）树的数目。
        # criterion:string,optional(default=”gini”)  衡量分裂质量的性能（函数）。
        # 百度。。。https://blog.csdn.net/ustbbsy/article/details/79541546
        self.rf_classifier = RandomForestClassifier(n_estimators=10, max_depth=None, min_samples_split=2,
                                                    random_state=0)
        self.rf_classifier.fit(self.x_train, self.y_train)

        # with open('model', 'rb') as f:
          #   self.rf_classifier = cPickle.load(f)

        # 准确率
        print("[随机森林算法]训练集分数：%s" %self.rf_classifier.score(self.x_train, self.y_train))
        print("[随机森林算法]测试集分数：%s" %self.rf_classifier.score(self.x_test, self.y_test))



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

        # Plot the feature importances of the forest
        plt.figure()
        plt.title("Feature importances")
        plt.bar(range(self.x.shape[1]), self.importances[indices],
                color="r", yerr=std[indices], align="center")
        plt.xticks(range(self.x.shape[1]), indices)
        plt.xlim([-1, self.x.shape[1]])
        plt.ylabel('Percent')
        plt.xlabel('Parameter index')

        plt.show()

    # source: Scikit-learn Documentation
    """
    此函数打印并绘制混淆矩阵。
    可以通过设置“ normalize = True”来应用规范化。
    """
    def plot_confusion_matrix(self, cm, classes,
                              normalize=False,
                              title='Confusion matrix',
                              cmap=plt.cm.Blues):

        plt.imshow(cm, interpolation='nearest', cmap=cmap)
        plt.title(title)
        tick_marks = np.arange(len(classes))
        plt.xticks(tick_marks, classes, rotation=0)
        plt.yticks(tick_marks, classes)

        if normalize:
            cm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
            print("规范化后的混淆矩阵")
        else:
            print('未规范化的混淆矩阵')

        print(cm)

        thresh = cm.max() / 2.
        for i, j in itertools.product(range(cm.shape[0]), range(cm.shape[1])):
            plt.text(j, i, cm[i, j], fontsize=20,
                     horizontalalignment="center",
                     color="white" if cm[i, j] > thresh else "black")

        plt.tight_layout()
        plt.ylabel('Actual')
        plt.xlabel('Predicted')
        plt.show()

    # （二分类模型）绘制预测模型，准确率
    # https://baijiahao.baidu.com/s?id=1619821729031070174&wfr=spider&for=pc 模型评估之混淆矩阵（confusion_matrix）含义
    def plot_predicted_model(self):
        # Predicted Model

        self.y_pred = self.rf_classifier.predict(self.x_test)
        self.cm = confusion_matrix(y_true=self.y_test, y_pred=self.y_pred)
        # self.plot_confusion_matrix(self.cm, self.labelencoder_y.classes_)
        # TN = 73785    # (True Negative)   ：将负类预测为负类数,真实为1,预测为1
        # FN = 294      # (False Negative)  ：将正类预测为负类数,真实为0,预测为1
        # TP = 73977    # (True Positive)   ：将正类预测为正类数,真实为0,预测为0
        # FP = 27       # (False Positive)  ：将负类预测为正类数,真实为1,预测为0
        # .ravel()就是把矩阵拉成一维的
        TN, FP, FN, TP = confusion_matrix(y_true=self.y_test, y_pred=self.y_pred).ravel()
        self.plot_confusion_matrix(self.cm, self.labelencoder_y.classes_)

        print("正类预测的准确率: %f" % (TP*1.0 / (TP + FN)))
        print("负类预测的准确率: %f" % (TN*1.0 / (TN + FP)))

        correct_predictions = TN + TP
        total_predictions = TN + FN + TP + FP
        print("总的准确率(公式): %f" % (correct_predictions*1.0 / total_predictions))

        print("总的准确率(机器): %f" % accuracy_score(self.y_test, self.y_pred))

    def plot_grid_search(self):
        self.forest = RandomForestClassifier(random_state=1)
        self.param_grid = {
            'n_estimators': [5, 10],
            'max_depth': [3, None],
            'max_features': [1, 3, 5],
            'min_samples_split': [2, 5],
            'min_samples_leaf': [2, 5],
            'bootstrap': [True, False],
            'criterion': ['gini', 'entropy']
        }
        # 模型调参利器 gridSearchCV（网格搜索）
        self.grid = GridSearchCV(estimator=self.forest, param_grid=self.param_grid, cv=2)
        self.grid.fit(self.x_train, self.y_train)
        print (self.grid.best_estimator_)
        print ("\nBest Score: ", self.grid.best_score_)

        self.grid.score(self.x_test, self.y_test)

        # self.cm = confusion_matrix(self.y_train, self.grid.predict(self.x_train))
        # self.plot_confusion_matrix(self.cm, classes=["B", "M"], title="Confusion Matrix (Train)")

        # self.cm = confusion_matrix(self.y_test, self.grid.predict(self.x_test))
        # self.plot_confusion_matrix(self.cm, classes=["B", "M"], title="Confusion Matrix (Test)")

    def plot_results(self, model, param='max_depth', name='Num Trees'):
        param_name = 'param_%s' % param

        # Extract information from the cross validation model
        train_scores = model.cv_results_['mean_train_score']
        test_scores = model.cv_results_['mean_test_score']
        train_time = model.cv_results_['mean_fit_time']
        param_values = list(model.cv_results_[param_name])

        # Plot the scores over the parameter
        plt.subplots(1, 2, figsize=(15, 6))
        plt.subplot(121)
        plt.plot(param_values, train_scores, 'bo-', label='train')
        plt.plot(param_values, test_scores, 'go-', label='test')
        plt.ylim(ymin=0.96, ymax=1.0)
        # plt.ylim(ymin = 0.990, ymax = 1.0)
        plt.legend()
        plt.xlabel(name)
        plt.ylabel('Accuracy')
        plt.title('Accuracy vs %s' % name)

        plt.subplot(122)
        plt.plot(param_values, train_time, 'ro-')
        plt.ylim(ymin=0.0, ymax=60.0)
        plt.xlabel(name)
        plt.ylabel('Train Time (sec)')
        plt.title('Training Time vs %s' % name)

        plt.tight_layout(pad=4)
        plt.show()

    def plot_GS_Acc_vs_Max_Feature(self):
        # Define a grid over only the maximum number of features
        # 仅在最大要素数量上定义网格
        self.feature_grid = {'max_features': list(range(1, self.x_train.shape[1] + 1))}
        # feature_grid = {'max_features': list(range(1, 15))}

        # Create the grid search and fit on the training data
        # 创建网格搜索并适合训练数据
        self.feature_grid_search = GridSearchCV(self.rf_classifier, param_grid=self.feature_grid, cv=3, n_jobs=-1,
                                                verbose=2,
                                                scoring='accuracy', return_train_score=True)
        self.feature_grid_search.fit(self.x_train, self.y_train)

        self.plot_results(self.feature_grid_search, param='max_features', name='Max Features')

    def plot_GS_Acc_vs_estimators(self):
        # Define a grid over only the maximum number of features
        self.feature_grid = {'n_estimators': [1, 3, 5, 7, 10, 12, 15]}
        # feature_grid = {'max_features': list(range(1, 15))}

        # Create the grid search and fit on the training data
        self.feature_grid_search = GridSearchCV(self.rf_classifier, param_grid=self.feature_grid, cv=3, n_jobs=-1,
                                                verbose=2,
                                                scoring='accuracy', return_train_score=True)
        self.feature_grid_search.fit(self.x_train, self.y_train)

        self.plot_results(self.feature_grid_search, param='n_estimators', name='Nbr. of Estimators')

    def plot_GS_Acc_vs_depth(self):
        # Define a grid over only the maximum number of features
        self.feature_grid = {'max_depth': [2, 3, 5, 7, 9, 11, 13, 15]}
        # feature_grid = {'max_features': list(range(1, 15))}

        # Create the grid search and fit on the training data
        self.feature_grid_search = GridSearchCV(self.rf_classifier, param_grid=self.feature_grid, cv=3, n_jobs=-1,
                                                verbose=2,
                                                scoring='accuracy', return_train_score=True)
        self.feature_grid_search.fit(self.x_train, self.y_train)

        self.plot_results(self.feature_grid_search, param='max_depth', name='Max Depth')

    def plot_GS_Acc_vs_Criterian(self):
        # Define a grid over only the maximum number of features
        self.feature_grid = {'criterion': ['gini', 'entropy']}
        # feature_grid = {'max_features': list(range(1, 15))}

        # Create the grid search and fit on the training data
        self.feature_grid_search = GridSearchCV(self.rf_classifier, param_grid=self.feature_grid, cv=3, n_jobs=-1,
                                                verbose=2,
                                                scoring='accuracy', return_train_score=True)
        self.feature_grid_search.fit(self.x_train, self.y_train)

        # scoring = ['accuracy', 'precision']

        self.plot_results(self.feature_grid_search, param='criterion', name='Criterion')

    # threshold：阈值
    # 针对每一个特征值，把散点图画出来，并把阈值画出来
    def feature_plot_array(self, x, i, threshold):

        # fig, ax = plt.subplots()

        # plt.subplot(8,2,i+1)

        base = np.arange(len(x))
        plt.grid(True)

        cmap = LinearSegmentedColormap.from_list('custom blue',
                                                 [(0, '#ff0000'),
                                                  (1, '#00ff00')], N=256)

        # plt.plot(base, x, c='blue')
        # 画散点图
        plt.scatter(base, x, c=self.feature_y, cmap=cmap, marker='.')
        # plt.title(param_array[i][0] + " - " + param_array[i][1])
        plt.title(self.feature_param_array[i][1])

        # plot threshold 把阈值画出来
        plt.axhline(y=threshold, color='blue')

        # plt.legend()函数，给图像加上图例。
        blue_plus = mlines.Line2D([], [], color='#00ff00', marker='.', linestyle='None',
                                  markersize=10, label='Clean Host')
        purple_plus = mlines.Line2D([], [], color='#ff0000', marker='.', linestyle='None',
                                    markersize=10, label='Infected Host')
        threshold_plus = mlines.Line2D([0, 1], [0, 1], color='blue', marker='_', linestyle='solid',
                                       markersize=10, label='Threshold')

        plt.legend(loc='upper left', handles=[blue_plus, purple_plus, threshold_plus], shadow=True, fontsize='large',
                   fancybox=True, frameon=True)

        # labels，设置坐标轴字体
        plt.xlabel('DNS fingerprint Index')
        # plt.ylabel(param_array[i][1])
        # xmin：x轴上的最小值；xmax：x轴上的最大值
        # xlim设置x轴的数值显示范围。
        plt.xlim([0, len(x) - 1])
        plt.show()

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

        for i in np.arange(15):
            if i == 0:
                self.feature_plot_array(self.feature_x[:, i], i, self.feature_param_array[i][2])
            self.feature_plot_array(self.feature_x[:, i], i, self.feature_param_array[i][2])

        # plt.show


if __name__ == '__main__':

    obj = BotDAD()

    obj.import_db()

    obj.encode_values()
    obj.display_count()
    obj.split_data()

    obj.feature_plot()

    obj.create_forest()
    obj.show_feature_imp()
    obj.plot_predicted_model()

    obj.plot_grid_search()

    obj.plot_GS_Acc_vs_Max_Feature()
    obj.plot_GS_Acc_vs_estimators()
    obj.plot_GS_Acc_vs_depth()

    obj.plot_GS_Acc_vs_Criterian()

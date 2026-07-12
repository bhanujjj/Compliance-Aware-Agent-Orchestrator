# This Python 3 environment comes with many helpful analytics libraries installed
# It is defined by the kaggle/python Docker image: https://github.com/kaggle/docker-python

# Input data files are available in the read-only "../input/" directory
# For example, running this (by clicking run or pressing Shift+Enter) will list all files under the input directory

import os
for dirname, _, filenames in os.walk('/kaggle/input'):
    for filename in filenames:
        print(os.path.join(dirname, filename))

# You can write up to 20GB to the current directory (/kaggle/working/) that gets preserved as output when you create a version using "Save & Run All" 
# You can also write temporary files to /kaggle/temp/, but they won't be saved outside of the current session

import pandas as pd
import numpy as np

from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import plot_confusion_matrix
import matplotlib.pyplot as plt

random_state = 5
np.random.seed(random_state)

data = pd.read_csv('../input/02152018-threats/02-15-2018.csv')

traffic_df = data #Keep original loaded file unchanged

with pd.option_context('display.max_columns', None,):
    print(traffic_df.head(10))

traffic_df[['Label']].groupby(['Label']).size()

columns_with_NaNs = traffic_df.isna().any()
traffic_df[columns_with_NaNs.index[columns_with_NaNs]]

columns_with_NaNs_df = traffic_df[columns_with_NaNs.index[columns_with_NaNs]]
columns_with_NaNs_df[columns_with_NaNs_df.isna().any(axis=1)]

traffic_df[columns_with_NaNs_df.isna().any(axis=1)][['Label']].groupby(['Label']).count()

columns_with_infs = np.isinf(traffic_df.select_dtypes(include=[np.number])).any()
inf_df = traffic_df[columns_with_infs.index[columns_with_infs]]
np.isinf(inf_df).sum()

index_with_label = inf_df.columns
index_with_label = index_with_label.append(pd.Index(['Label']))
traffic_df[index_with_label]

traffic_df[[inf_df.columns[0],'Label']][np.isinf(inf_df[inf_df.columns[0]])].groupby(['Label']).count()

traffic_df[[inf_df.columns[1],'Label']][np.isinf(inf_df[inf_df.columns[1]])].groupby(['Label']).count()

column_unique_counts = traffic_df.nunique()
with pd.option_context('display.max_rows', None,):
    print(column_unique_counts)

for i in range(1,11):
    df_with_n_uniques = traffic_df[column_unique_counts.index[column_unique_counts == i]]
    if not df_with_n_uniques.empty:
        num_of_columns = len(df_with_n_uniques.columns)
        print(f"\n--- {num_of_columns} columns have {i} unique values:")
        for c in df_with_n_uniques.columns:
            print("\n",df_with_n_uniques[c].value_counts())
    else:
        print(f"\nNo columns have {i} unique values.")

datasize = traffic_df.shape[0]
labels = traffic_df[['Label']].groupby(['Label']).size().index
for label in labels:
    percentage = np.round(traffic_df[['Label']][traffic_df['Label'] == label].shape[0]/datasize*100,2)
    print(f'{label} comprises {percentage}% of the dataset.')

with pd.option_context('mode.use_inf_as_na', True):
    traffic_df = traffic_df.dropna(how='any')
traffic_df.shape[0]

is_there_nan = traffic_df.isna().any().any()
is_there_nan

#Drop columns with 1 unique values
traffic_df = traffic_df[column_unique_counts.index[column_unique_counts != 1]]
traffic_df.nunique()

traffic_df['Timestamp'] = pd.to_datetime(traffic_df['Timestamp'],infer_datetime_format = True)
traffic_df['Timestamp'].dtype

skip_columns = ['Timestamp','Label']

for i,c in enumerate(traffic_df.columns.difference(skip_columns)):
    traffic_df.hist(column=c, by='Label',figsize=(18,5), layout=(1,3), legend=True, color=f'C{i}',sharex=True)

ax = traffic_df.hist(column='Timestamp', by='Label',figsize=(18,5), layout=(1,3), legend=True,bins=10,sharex=True)

traffic_df = traffic_df.drop('Timestamp', axis=1)
traffic_df

traffic_df['Label'].value_counts(normalize = True)

#Randomly sample dataset
test_ratio = 0.25
train_df = traffic_df.sample(frac=1-test_ratio, random_state = random_state)
train_df['Label'].value_counts(normalize = True)

train_df

test_df = traffic_df.drop(train_df.index)
test_df['Label'].value_counts(normalize = True)

test_df

dst_port = 'Dst Port'
traffic_df[[dst_port]].groupby([dst_port]).size().sort_values(ascending=False).shape[0]

class BinColumn(BaseEstimator, TransformerMixin):
    def __init__(self,column_name,target_bins=5):
        self.column_name = column_name
        self.bins = target_bins-1
        
    def fit(self,X,y=None):
        bins_se = X[[self.column_name]].groupby([self.column_name]).size().sort_values(ascending=False)
        self.top_bins_names = bins_se[:self.bins]
        return self
    
    def transform(self,X):
        lower_counts_df = X[~np.isin(X[self.column_name],self.top_bins_names.index)]
        lower_counts_df = lower_counts_df.copy()
        lower_counts_df.loc[:,(self.column_name,)] = 'other'
        top_counts_df = X[np.isin(X[self.column_name],self.top_bins_names.index)]
        return pd.concat([lower_counts_df, top_counts_df])
        

#Fit and transform the training set
bins_num = 5
binner = BinColumn(dst_port,bins_num)
binner.fit(train_df) #Get bins using the training set 
train_df = binner.transform(train_df)#.drop('Label',axis = 1)).join(train_df[['Label']])
train_df[[dst_port]].groupby([dst_port]).size()

train_df

#Transform the test set
test_df = binner.transform(test_df)
test_df

#Check columns with small number of values
column_unique_counts = traffic_df.nunique().sort_values()
column_unique_counts.head(50)

# Get columns with 5 or less unique values
column_unique_counts = train_df.nunique()
categorical_columns = traffic_df[column_unique_counts.index[((column_unique_counts >= 1) & (column_unique_counts <= 5)) ]].columns
categorical_columns

traffic_df[categorical_columns]

class PaucalOneHotter(BaseEstimator, TransformerMixin):
    def __init__(self,max_number_of_categories,drop_column):
        self.max_number_of_categories = max_number_of_categories
        self.drop_column = drop_column
        
    def fit(self,X,y=None):
        column_unique_counts = X.nunique()
        categorical_columns = X[column_unique_counts.index[((column_unique_counts >= 2) & (column_unique_counts <= self.max_number_of_categories)) ]].columns
        self.categorical_columns = categorical_columns.difference([self.drop_column])
        return self
    
    def transform(self,X):
        X[self.categorical_columns] = X[self.categorical_columns].astype('str') #Convert all categorical columns to strings
        train_dummies_df = pd.get_dummies(X[self.categorical_columns])
        X = X.drop(self.categorical_columns,axis=1).join(train_dummies_df)
        return X
        
        


p_one_hotter = PaucalOneHotter(bins_num,'Label') #Use the number of bins as a paucity threshold
p_one_hotter.fit(train_df)
train_df = p_one_hotter.transform(train_df)
train_df

test_df = p_one_hotter.transform(test_df)
test_df

#Class correction ratios
counts = train_df['Label'].value_counts().sort_values()
print(counts)
class_ratios = [counts[0]/counts[i] for i in range(len(counts))]
class_ratios

temp_df = pd.DataFrame()
for i,lbl in enumerate(counts.index):
    print(i,lbl)
    temp_df = pd.concat([temp_df,train_df[train_df['Label'] == lbl].sample(frac=class_ratios[i])])
temp_df

temp_df['Label'].value_counts()

#Omit onehot columns for scaling; these are the columns that have exactly two unique values

columns_unique_counts = train_df.nunique()
one_hot_columns = columns_unique_counts[columns_unique_counts==2].index
temp_df[temp_df.columns.difference(one_hot_columns)]

columns_to_scale = temp_df.columns.difference(one_hot_columns.union(['Label']))
columns_to_scale

sc = StandardScaler()
temp_df[columns_to_scale] = sc.fit_transform(temp_df[columns_to_scale])

temp_df

test_df[columns_to_scale] = sc.transform(test_df[columns_to_scale] )

test_df

# Random Forest Classifier
rf_clf = RandomForestClassifier(n_estimators=50, random_state = random_state)
rf_clf.fit(temp_df.drop('Label', axis=1),temp_df['Label'])


rf_clf.score(test_df.drop('Label',axis=1),test_df['Label'])

from sklearn.metrics import ConfusionMatrixDisplay

ConfusionMatrixDisplay.from_estimator(rf_clf,test_df.drop('Label',axis=1),test_df['Label'],values_format = '', xticks_rotation = 'vertical')
plt.grid(False)

# Random Forest Classifier
rf_clf_sc = RandomForestClassifier(n_estimators=50, random_state = random_state)
rf_clf_sc.fit(temp_df[columns_to_scale],temp_df['Label'])

rf_clf_sc.score(test_df[columns_to_scale],test_df['Label'])

ConfusionMatrixDisplay.from_estimator(rf_clf_sc,test_df[columns_to_scale],test_df['Label'],values_format = '', xticks_rotation = 'vertical')
plt.grid(False)

from sklearn.neighbors import KNeighborsClassifier

knn_clf = KNeighborsClassifier()
knn_clf.fit(temp_df.drop('Label', axis=1),temp_df['Label'])
knn_clf.score(test_df.drop('Label',axis=1),test_df['Label'])

ConfusionMatrixDisplay.from_estimator(knn_clf,test_df.drop('Label',axis=1),test_df['Label'],values_format = '', xticks_rotation = 'vertical')
plt.grid(False)

from sklearn.svm import SVC

svc_clf = SVC()
svc_clf.fit(temp_df.drop('Label', axis=1),temp_df['Label'])


svc_clf.score(test_df.drop('Label',axis=1),test_df['Label'])

ConfusionMatrixDisplay.from_estimator(svc_clf,test_df.drop('Label',axis=1),test_df['Label'],values_format = '', xticks_rotation = 'vertical')
plt.grid(False)

from sklearn.metrics import classification_report
target_values = test_df['Label'].value_counts().sort_values(ascending = False).index

print("First random forest:\n",classification_report(test_df['Label'], rf_clf.predict(test_df.drop('Label',axis=1)), target_names=target_values,digits = 5))

print("kNN:\n",classification_report(test_df['Label'], knn_clf.predict(test_df.drop('Label',axis=1)), target_names=target_values,digits = 5))

print("SVC:\n",classification_report(test_df['Label'], svc_clf.predict(test_df.drop('Label',axis=1)), target_names=target_values,digits = 5))

from yellowbrick.classifier import ROCAUC
vis = ROCAUC(rf_clf, classes=target_values)
vis.fit(temp_df.drop('Label', axis=1),temp_df['Label'])  
vis.score(test_df.drop('Label',axis=1), test_df['Label'])
vis.show()

rf3_clf = RandomForestClassifier(n_estimators = 1,max_depth=2)
rf3_clf.fit(temp_df.drop('Label', axis=1),temp_df['Label'])

print(classification_report(test_df['Label'], rf3_clf.predict(test_df.drop('Label',axis=1)), target_names=target_values,digits = 5))

visualizer = ROCAUC(rf3_clf, classes=target_values)
visualizer.fit(temp_df.drop('Label', axis=1),temp_df['Label'])  
visualizer.score(test_df.drop('Label',axis=1), test_df['Label'])
visualizer.show()

binner2 = BinColumn(dst_port,bins_num)
binner2.fit(traffic_df)
traffic_df = binner2.transform(traffic_df)
traffic_df[[dst_port]].groupby([dst_port]).size()

p_one_hotter2 = PaucalOneHotter(bins_num,'Label')
p_one_hotter2.fit(traffic_df)
traffic_df = p_one_hotter2.transform(traffic_df)
traffic_df

sc2 = StandardScaler()
traffic_df[columns_to_scale] = sc2.fit_transform(traffic_df[columns_to_scale])

traffic_df = traffic_df.drop('Label',axis=1) #Label need not be present in the clustering data

traffic_df

from sklearn.cluster import KMeans
km_models = {}
for i in range(1,21):
    print(f'Fitting {i}-cluster model ...')
    kmeans = KMeans(n_clusters=i, max_iter=1000, random_state = random_state)
    km_models[i] = kmeans.fit(traffic_df)
    inertia = km_models[i].inertia_
    print(f'  Inertia = {inertia}')


from matplotlib.pyplot import gcf
sum_of_sq_errs = [(key, val.inertia_) for key, val in km_models.items()]
sum_of_sq_errs = zip(*sum_of_sq_errs)
fig = gcf()
fig.set_size_inches(18.5, 10.5)
plt.plot(*sum_of_sq_errs)

for key, val in km_models.items():
    print(f'\nThe {key}-cluster model has the clusters:')
    arr = np.array(val.labels_)
    u, c = np.unique(arr, return_counts = True)
    print(u,'\nThe corresponding counts are:\n', c)
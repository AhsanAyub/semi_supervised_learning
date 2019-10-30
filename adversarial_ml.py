__author__ = "Md. Ahsan Ayub"
__license__ = "GPL"
__credits__ = ["Ayub, Md. Ahsan", "Johnson, Will",
               "Siraj, Ambareen"]
__maintainer__ = "Md. Ahsan Ayub"
__email__ = "mayub42@students.tntech.edu"
__status__ = "Prototype"


# Generate a multilayer perceptron  model or ANN
def mlp_model(X, Y):
    
    # Initializing the ANN
    model = Sequential()
    
    # Adding the input layer and the first hidden layer
    model.add(Dense(output_dim = round(X.shape[1]/2), init =  'uniform', activation = 'relu', input_dim = X.shape[1]))
    
    # Adding the second hidden layer
    model.add(Dense(output_dim = round(X.shape[1]/2), init =  'uniform', activation = 'relu'))

    
    if(len(np.unique(Y)) > 2): # Multi-classification task
        # Adding the output layer
        model.add(Dense(output_dim = len(np.unique(Y)), init =  'uniform', activation = 'softmax'))
        # Compiling the ANN
        model.compile(optimizer = 'adam', loss = 'sparse_categorical_crossentropy', metrics = ['accuracy'])
    else: # Binary classification task
        # Adding the output layer
        model.add(Dense(output_dim = 1, init =  'uniform', activation = 'sigmoid'))
        # Compiling the ANN
        model.compile(optimizer = 'adam', loss = 'binary_crossentropy', metrics = ['accuracy'])
    
    print(model.summary())
    
    return model

'''def evaluate():
    eval_params = {
        'batch_size': 64
        }
    accuracy = model_eval(sess, X_placeholder, Y_placeholder, predictions , X_test , Y_test, args=eval_params)
    print('Test  accuracy  on  legitimate  test  examples: ' + str(accuracy))'''

# import libraries
import numpy as np
import pandas as pd
import tensorflow as tf
import matplotlib.pyplot as plt

# importing cleverhans - an adversarial example library
import cleverhans
from cleverhans.attacks import SaliencyMapMethod
from cleverhans.attacks import FastGradientMethod
from cleverhans.utils_tf import model_train, model_eval, batch_eval
from cleverhans.attacks_tf import jacobian_graph
from cleverhans.utils import other_classes

# Libraries relevant to performance metrics
from sklearn.metrics import roc_curve, auc, confusion_matrix, classification_report, accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import StratifiedKFold
from scipy import interp
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split

# Importing the Keras libraries and packages
from keras.models import Sequential
from keras.layers import Dense
from keras.callbacks import EarlyStopping

#importing the data set
dataset = pd.read_csv('sample_dataset.csv')
print(dataset.head())

# Creating X and Y from the dataset
from sklearn import preprocessing
le = preprocessing.LabelEncoder()
le.fit(dataset['Label'])
Y_attack = le.transform(dataset['Label'])
print(list(le.classes_))
print(np.unique(Y_attack))
Y_class = dataset.iloc[:,-1].values
X = dataset.iloc[:,0:80].values
X = X.astype(int)

# Performing scale data
scaler = MinMaxScaler().fit(X)
X_scaled = np.array(scaler.transform(X))

X_train, X_test, Y_train, Y_test = train_test_split(X_scaled, Y_class, test_size = 0.2, random_state = 42, stratify=Y_class)

# Tensorflow  placeholder  variables
X_placeholder = tf.placeholder(tf.float32 , shape=(None , X_train.shape[1]))
Y_placeholder = tf.placeholder(tf.float32 , shape=(None))

tf.set_random_seed(42)
model = mlp_model(X_train, Y_train)
sess = tf.Session()
init = tf.global_variables_initializer()
sess.run(init)

predictions = model(X_placeholder)
print('Prediction: ', predictions)

# ============== Training the model ==============

# Callback to stop if validation loss does not decrease
callbacks = [EarlyStopping(monitor='val_loss', patience=2)]

# Fitting the ANN to the Training set
history = model.fit(X_train,
               Y_train,
               callbacks=callbacks,
               validation_split=0.1,
               batch_size = 64,
               epochs = 100,
               shuffle=True)

print(history.history)
print(model.summary())


# ============== Training the model ==============

print("Performance when using actual testing instances")
    
# Predicting the Test set results
Y_pred = model.predict_classes(X_test)
Y_pred = (Y_pred > 0.5)

# Breakdown of statistical measure based on classes
print(classification_report(Y_test, Y_pred, digits=4))

# Making the cufusion Matrix
cm = confusion_matrix(Y_test, Y_pred)
print("Confusion Matrix (Actual):\n", cm)
print("Accuracy (Actual): ", accuracy_score(Y_test, Y_pred))

if(len(np.unique(Y_test))) == 2:
    print("F1 (Actual): ", f1_score(Y_test, Y_pred, average='binary'))
    print("Precison (Actual): ", precision_score(Y_test, Y_pred, average='binary'))
    print("Recall (Actual): ", recall_score(Y_test, Y_pred, average='binary'))
else:
    f1_scores = f1_score(Y_test, Y_pred, average=None)
    print("F1 (Actual): ", np.mean(f1_scores))
    precision_scores = precision_score(Y_test, Y_pred, average=None)
    print("Precison (Actual): ", np.mean(precision_scores))
    recall_scores = recall_score(Y_test, Y_pred, average=None)
    print("Recall (Actual): ", np.mean(recall_scores))

'''# Train the params
train_params = {
        'nb_epochs': 10,
        'batch_size': 64,
        'learning_rate': 0.1,
        'verbose': 0
        }

print("Shape of X's: ", X_placeholder.shape, X_train.shape)
print("Shape of Y's: ", Y_placeholder.shape, Y_train.shape)

#model_train(sess, X_placeholder, Y_placeholder, predictions, X_train, Y_train, evaluate = evaluate, args = train_params)'''

# ============== Generate adversarial samples for all test datapoints ==============

source_samples = X_test.shape[0]

# Jacobian-based Saliency Map
results = np.zeros((1, source_samples), dtype=float)
perturbations = np.zeros((1, source_samples), dtype=float)
grads = jacobian_graph(predictions , X_placeholder, 1)

X_adv = np.zeros((source_samples, X_test.shape[1]))

for sample_ind in range(0, source_samples):
    # We want to find an  adversarial  example  for  each  possible  target  class
    # (i.e. all  classes  that  differ  from  the  label  given  in the  dataset)
    current_class = int(np.argmax(Y_test[sample_ind]))
    
    # Target the benign class
    for target in [0]:
        if (current_class == 0):
            break
        
        # This call runs the Jacobian-based saliency map approac
        adv_x , res , percent_perturb = SaliencyMapMethod(sess, X_placeholder, predictions , grads,
                                             X_test[sample_ind: (sample_ind+1)],
                                             target , theta=1, gamma =0.1,
                                             increase=True ,
                                             clip_min=0, clip_max=1)
        
        X_adv[sample_ind] = adv_x
        results[target , sample_ind] = res
        perturbations[target , sample_ind] = percent_perturb

'''# Evaluation of MLP performance
eval_params = {
        'batch_size': 64
        }

accuracy_adv = model_eval(sess, X_placeholder, Y_placeholder, predictions, X_adv, Y_test, args=eval_params)
print(accuracy_adv)'''

print("Performance when using adversarial testing instances")

# Predicting the Test set results
Y_pred_adv = model.predict_classes(X_adv)
Y_pred_adv = (Y_pred_adv > 0.5)

# Breakdown of statistical measure based on classes
print(classification_report(Y_test, Y_pred_adv, digits=4))

# Making the cufusion Matrix
cm = confusion_matrix(Y_test, Y_pred_adv)
print("Confusion Matrix (Adversarial):\n", cm)
print("Accuracy (Adversarial): ", accuracy_score(Y_test, Y_pred_adv))

if(len(np.unique(Y_test))) == 2:
    print("F1 (Adversarial): ", f1_score(Y_test, Y_pred_adv, average='binary'))
    print("Precison (Adversarial): ", precision_score(Y_test, Y_pred_adv, average='binary'))
    print("Recall (Adversarial): ", recall_score(Y_test, Y_pred_adv, average='binary'))
else:
    f1_scores = f1_score(Y_test, Y_pred_adv, average=None)
    print("F1: ", np.mean(f1_scores))
    precision_scores = precision_score(Y_test, Y_pred_adv, average=None)
    print("Precison (Adversarial): ", np.mean(precision_scores))
    recall_scores = recall_score(Y_test, Y_pred_adv, average=None)
    print("Recall (Adversarial): ", np.mean(recall_scores))

X_adv.dumps("X_adv.csv")
X_test.dumps("X_test.csv")
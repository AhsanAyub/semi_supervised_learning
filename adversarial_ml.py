__author__ = "Md. Ahsan Ayub"
__license__ = "GPL"
__credits__ = ["Ayub, Md. Ahsan", "Johnson, Will",
               "Siraj, Ambareen"]
__maintainer__ = "Md. Ahsan Ayub"
__email__ = "mayub42@students.tntech.edu"
__status__ = "Prototype"


# Generate a multilayer perceptron  model or ANN
def mlp_model(X, Y, batchSize, epochCount):
    
    # Spliting the dataset into the Training and Test Set
    from sklearn.model_selection import train_test_split
    X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size = 0.2, random_state = 42, stratify=Y)
    
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


# import libraries
import numpy as np
import pandas as pd
import tensorflow as tf
import matplotlib.pyplot as plt

# importing cleverhans - an adversarial example library
import cleverhans
from cleverhans.attacks import fgsm, jsma
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

X_train, X_test, Y_train, Y_test = train_test_split(X_scaled, Y_class, test_size = 0.2, random_state = 42, stratify=Y)

# Tensorflow  placeholder  variables
X_placeholder = tf.placeholder(tf.float32 , shape=(None , X_train.shape[1]))
Y_placeholder = tf.placeholder(tf.float32 , shape=(None , len(np.unique(Y_class))))

tf.set_random_seed(42)
model = mlp_model()
sess = tf.Session()
predictions = model(X_train)
init = tf.global_variables_initializer()
sess.run(init)

# Train the params
train_params = {
        'nb_epochs': 100,
        'batch_size': 64,
        'learning_rate': 0.1,
        'verbose': 0
        }

model_train(sess, X_placeholder, Y_placeholder, predictions, X_train, Y_train, evaluate = evaluate, args = train_params)

# Generate adversarial samples for all test datapoints
source_samples = X_test.shape[0]

# Jacobian-based Saliency Map
results = np.zeros((len(np.unique(Y_class)), source_samples), dtype=’i’)
perturbations = np.zeros((len(np.unique(Y_class)), source_samples), dtype=’f’)
grads = jacobian_graph(predictions , X_placeholder, len(np.unique(Y_class)))

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
        adv_x , res , percent_perturb = jsma(sess, X_placeholder, predictions , grads,
                                             X_test[sample_ind: (sample_ind+1)],
                                             target , theta=1, gamma =0.1,
                                             increase=True , back=’tf’,
                                             clip_min=0, clip_max=1)
        
        X_adv[sample_ind] = adv_x
        results[target , sample_ind] = res
        perturbations[target , sample_ind] = percent_perturb
        

print(X_adv.shape)

# Evaluation of MLP performance

eval_params = {’batch_size ’: 64}
accuracy = model_eval(sess, X_placeholder, Y_placeholder, predictions, X_test, Y_test, args=eval_params)
print(accuracy)

accuracy_adv = model_eval(sess, X_placeholder, Y_placeholder, predictions, X_adv, Y_test, args=eval_params)
print(accuracy_adv)
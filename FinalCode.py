import os
import pandas as pd
import random
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from ReadingDataset import get_pe_info  # Make sure this is correctly pointed to your PE file processing function

import numpy as np  # Ensure numpy is imported

class Node:
    def __init__(self, data=None):
        self.data = data
        self.next = None

class LinkedList:
    def __init__(self):
        self.head = None

    def append(self, data):
        if not self.head:
            self.head = Node(data)
        else:
            current = self.head
            while current.next:
                current = current.next
            current.next = Node(data)

    def to_list(self):
        current = self.head
        data_list = []
        while current:
            data_list.append(current.data.__dict__)
            current = current.next
        return data_list
    def calculate_scores(self):
        current = self.head
        scores = []
        while current:
            scores.append(current.data.calculate_static_score())
            current = current.next
        return scores
class DynamicMalwareData:
    # Actual API calls with assigned weights
    api_weights = {
        'CreateProcess': 5,   # Often used to start new processes, possibly malicious
        'OpenProcess': 4,     # Used for accessing other processes, potentially for code injection
        'VirtualAllocEx': 5,  # Commonly used in memory injection scenarios
        'WriteProcessMemory': 5,  # Used to write data to another process's memory space
        'CreateRemoteThread': 5,  # Can be used for running code in the context of another process
        'SetWindowsHookEx': 4,    # Used for monitoring keyboard/mouse input, potentially for keylogging
        'RegSetValueEx': 3,       # Modifying the registry, could be used to establish persistence
        'HttpSendRequest': 3,     # Network function that could be used to communicate with C&C servers
        'ShellExecute': 2,        # Used to execute a program, potentially malicious if used in certain contexts
        'LoadLibrary': 3          # Loading a DLL, which could be malicious
    }

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def calculate_dynamic_score(self):
        total_api_calls = sum(getattr(self, api, 0) for api in self.api_weights)
        max_score = sum(self.api_weights[api] * 5 for api in self.api_weights)  # Maximum possible score if all calls occur 5 times
        score = sum(self.api_weights[api] * getattr(self, api, 0) for api in self.api_weights)
        return (score / max_score) * 100  # Normalize to a scale of 0-100

def generate_dynamic_scores(lenofstatic):
    # Create a list of dynamic malware data
    dynamic_data_list = []
    for _ in range(lenofstatic):  # Generate 100 entries
        api_data = {api: random.randint(0, 5) for api in DynamicMalwareData.api_weights}  # Random frequency from 0 to 5 for each API call
        malware_instance = DynamicMalwareData(**api_data)
        dynamic_data_list.append(api_data)
    
    # Convert to DataFrame
    dynamic_df = pd.DataFrame(dynamic_data_list)
    dynamic_df['dynamic_score'] = dynamic_df.apply(lambda row: DynamicMalwareData(**row).calculate_dynamic_score(), axis=1)
    return dynamic_df['dynamic_score'].tolist()
class MalwareData:
    weights = {
        'file_entropy': 5,
        'high_entropy_sections': 4,
        'repeated_section_names': 3,
        'non_standard_section_names': 3,
        'zero_raw_size_sections': 2,
        'sum_section_sizes_greater': 5,
        'section_alignment': 1,
        'file_alignment': 1,
        'pe_resource_count': 4,
        'no_image_version': 3,
        'malicious_import_functions': 5,
        'imports_related_to_packing': 4,
        'invalid_compile_time': 3
    }

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def calculate_static_score(self):
        score = sum(self.weights[key] * getattr(self, key, 0) for key in self.weights)
       # print(score)
        return score

# Example usage

pe_files_directory = r"C:\Users\Faheem\Downloads\b9079fb0fff9f40d7b5544f29d260b1659d8fcf019deadc72ec2c12882203a66"
linked_list = LinkedList()
for pe_file in os.listdir(pe_files_directory):
    pe_path = os.path.join(pe_files_directory, pe_file)
    pe_data = get_pe_info(pe_path)
    if pe_data:
        malware_data = MalwareData(**pe_data)
        linked_list.append(malware_data)

# Convert linked list to DataFrame
print("-----")
static_scores = linked_list.calculate_scores()
print("Static Analysis Scores:", static_scores)
lenofstatic=len(static_scores)
print(lenofstatic)

print("Dynamic Analysis Scores: ")
dynamic_scores = generate_dynamic_scores(lenofstatic)
print(dynamic_scores)



def calculate_hybrid_scores(static_scores, dynamic_scores, weight_static=0.7, weight_dynamic=0.3):
    """
    Calculates hybrid scores based on weighted averages of static and dynamic scores.
    
    Parameters: 
    static_scores (list): List of static analysis scores.
    dynamic_scores (list): List of dynamic analysis scores.
    weight_static (float): Weight for static scores.
    weight_dynamic (float): Weight for dynamic scores.
    
    Returns:
    list: Hybrid scores for each sample.
    """
    static_scores = np.array(static_scores)
    dynamic_scores = np.array(dynamic_scores)
    hybrid_scores = (static_scores * weight_static) + (dynamic_scores * weight_dynamic)
    return hybrid_scores.tolist()

def classify_files(hybrid_scores, threshold=3280):
    """
    Classifies files based on hybrid scores.
    
    Parameters:
    hybrid_scores (list): List of calculated hybrid scores.
    threshold (float): Threshold score to classify files as Malicious.
    
    Returns:
    list: Classification results for each sample.
    """
    return ["Malicious" if score > threshold else "Non-Malicious" for score in hybrid_scores]
    
hybrid_scores = calculate_hybrid_scores(static_scores, dynamic_scores)

# Classify files based on hybrid scores
classifications = classify_files(hybrid_scores) 
num_malicious = classifications.count("Malicious")
num_non_malicious = classifications.count("Non-Malicious")

# Print the hybrid scores, their classifications, and the count of malicious and non-malicious files
for score, classification in zip(hybrid_scores, classifications):
    print(f"Score: {score}, Classification: {classification}")
print("-----------------")
print(f"Number of Malicious files: {num_malicious}")
print(f"Number of Non-Malicious files: {num_non_malicious}")   
df = pd.DataFrame(linked_list.to_list())
df['StaticAnalysisScore'] = df.apply(lambda row: MalwareData(**row).calculate_static_score(), axis=1)

# Randomly assign labels
df['label'] = [random.choice([0, 1]) for _ in range(len(df))]

# Filter DataFrame where StaticAnalysisScore is greater than 70
df_filtered = df[df['StaticAnalysisScore'] < 8000]

# Remove non-numeric columns (assuming the 'Name' column contains filenames or other string identifiers)
X = df_filtered.select_dtypes(include=['number'])
y = df_filtered['label']

# Split data into training and test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.5, random_state=42)

# Train a Random Forest Classifier
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Predict and evaluate the model
predictions = model.predict(X_test)
print("Static Analysis Only Results")
print("Accuracy:", accuracy_score(y_test, predictions))
print("Classification Report:\n", classification_report(y_test, predictions))

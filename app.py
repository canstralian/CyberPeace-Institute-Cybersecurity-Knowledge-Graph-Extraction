import streamlit as st
from transformers import AutoModelForTokenClassification
from annotated_text import annotated_text
import numpy as np
import os, joblib

from utils import get_idxs_from_text

model = AutoModelForTokenClassification.from_pretrained("CyberPeace-Institute/Cybersecurity-Knowledge-Graph", trust_remote_code=True)

role_classifiers = {}
folder_path = '/arg_role_models'
for filename in os.listdir(os.getcwd() + folder_path):
    if filename.endswith('.joblib'):
        file_path = os.getcwd() + os.path.join(folder_path, filename)
        clf = joblib.load(file_path)
        arg = filename.split(".")[0]
        role_classifiers[arg] = clf

def annotate(name):
    tokens = [item["token"] for item in output]
    tokens = [token.replace(" ", "") for token in tokens]
    text = model.tokenizer.decode([item["id"] for item in output])
    idxs = get_idxs_from_text(text, tokens)
    labels = [item[name] for item in output]

    annotated_text_list = []
    last_label = ""
    cumulative_tokens = "" 
    last_id = 0
    for idx, label in zip(idxs, labels):
        to_label = label
        label_short = to_label.split("-")[1] if "-" in to_label else to_label
        if last_label == label_short:
            cumulative_tokens += text[last_id : idx["end_idx"]]
            last_id = idx["end_idx"]
        else:
            if last_label != "":
                if last_label == "O":
                    annotated_text_list.append(cumulative_tokens)
                else:
                    annotated_text_list.append((cumulative_tokens, last_label))
            last_label = label_short
            cumulative_tokens = idx["word"]
            last_id = idx["end_idx"]
    if last_label == "O":
        annotated_text_list.append(cumulative_tokens)
    else:  
        annotated_text_list.append((cumulative_tokens, last_label))
    annotated_text(annotated_text_list)

def get_arg_roles(output):
    args = [(idx, item["argument"], item["token"]) for idx, item in enumerate(output) if item["argument"]!= "O"]
        
    entities = []
    current_entity = None
    for position, label, token in args:
        if label.startswith('B-'):
            if current_entity is not None:
                entities.append(current_entity)
            current_entity = {'label': label[2:], 'text': token.replace(" ", ""), 'start': position, 'end': position}
        elif label.startswith('I-'):
            if current_entity is not None:
                current_entity['text'] += ' ' + token.replace(" ", "")
                current_entity['end'] = position
    for entity in entities:
        context = model.tokenizer.decode([item["id"] for item in output[max(0, entity["start"] - 15) : min(len(output), entity["end"] + 15)]])
        entity["context"] = context
    
    for entity in entities:
        if len(model.arg_2_role[entity["label"]]) > 1:
            sent_embed = model.embed_model.encode(entity["context"])
            arg_embed = model.embed_model.encode(entity["text"])
            embed = np.concatenate((sent_embed, arg_embed))
            arg_clf = role_classifiers[entity["label"]]
            role_id = arg_clf.predict(embed.reshape(1, -1))
            role = model.arg_2_role[entity["label"]][role_id[0]]
            entity["role"] = role
        else:
            entity["role"] = model.arg_2_role[entity["label"]][0]
    
    for item in output:
        item["role"] = "O"
    for entity in entities:
        for i in range(entity["start"], entity["end"] + 1):
            output[i]["role"] = entity["role"]
    return output

st.title("Create Knowledge Graphs from Cyber Incidents")

text_input = st.text_area("Enter your text here", height=100)

if text_input or st.button('Apply'):
    output = model(text_input)
    st.subheader("Event Nuggets")
    annotate("nugget")
    st.subheader("Event Arguments")
    annotate("argument")
    st.subheader("Realis of Event Nuggets")
    annotate("realis")
    output = get_arg_roles(output)
    st.subheader("Role of the Event Arguments")
    annotate("role")

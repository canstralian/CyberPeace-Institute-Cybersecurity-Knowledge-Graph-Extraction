list_of_pos_tags = [
    "ADJ",
    "ADP",
    "ADV",
    "AUX",
    "CCONJ",
    "DET",
    "INTJ",
    "NOUN",
    "NUM",
    "PART",
    "PRON",
    "PROPN",
    "PUNCT",
    "SCONJ",
    "SYM",
    "VERB",
    "X"
]

realis_list = ["O",
    "Generic", 
    "Other", 
    "Actual"
]


event_args_list = ['O',
    'B-System',
    'I-System',
    'B-Organization',
    'B-Money',
    'I-Money',
    'B-Device',
    'B-Person',
    'I-Person',
    'B-Vulnerability',
    'I-Vulnerability',
    'B-Capabilities',
    'I-Capabilities',
    'I-Organization',
    'B-PaymentMethod',
    'I-PaymentMethod',
    'B-Data',
    'I-Data',
    'B-Number',
    'I-Number',
    'B-Malware',
    'I-Malware',
    'B-PII',
    'I-PII',
    'B-CVE',
    'I-CVE',
    'B-Purpose',
    'I-Purpose',
    'B-File',
    'I-File',
    'I-Device',
    'B-Time',
    'I-Time',
    'B-Software',
    'I-Software',
    'B-Patch',
    'I-Patch',
    'B-Version',
    'I-Version',
    'B-Website',
    'I-Website',
    'B-GPE',
    'I-GPE'
]

event_nugget_list = ['O',
 'B-Ransom',
 'I-Ransom',
 'B-DiscoverVulnerability',
 'I-DiscoverVulnerability',
 'B-PatchVulnerability',
 'I-PatchVulnerability',
 'B-Databreach',
 'I-Databreach',
 'B-Phishing',
 'I-Phishing'
]

arg_2_role = {
    "File" : ['Tool', 'Trusted-Entity'],
    "Person" : ['Victim', 'Attacker', 'Discoverer', 'Releaser', 'Trusted-Entity', 'Vulnerable_System_Owner'],
    "Capabilities" : ['Attack-Pattern', 'Capabilities', 'Issues-Addressed'],
    "Purpose" : ['Purpose'],
    "Time" : ['Time'],
    "PII" : ['Compromised-Data', 'Trusted-Entity'],
    "Data" : ['Compromised-Data', 'Trusted-Entity'],
    "Organization" : ['Victim', 'Releaser', 'Discoverer', 'Attacker', 'Vulnerable_System_Owner', 'Trusted-Entity'],
    "Patch" : ['Patch'],
    "Software" : ['Vulnerable_System', 'Victim', 'Trusted-Entity', 'Supported_Platform'],
    "Vulnerability" : ['Vulnerability'],
    "Version" : ['Patch-Number', 'Vulnerable_System_Version'],
    "Device" : ['Vulnerable_System', 'Victim', 'Supported_Platform'],
    "CVE" : ['CVE'],
    "Number" : ['Number-of-Data', 'Number-of-Victim'],
    "System" : ['Victim', 'Supported_Platform', 'Vulnerable_System', 'Trusted-Entity'],
    "Malware" : ['Tool'],
    "Money" : ['Price', 'Damage-Amount'],
    "PaymentMethod" : ['Payment-Method'],
    "GPE" : ['Place'],
    "Website" : ['Trusted-Entity', 'Tool', 'Vulnerable_System', 'Victim', 'Supported_Platform'],
}

def get_content(data):
    return data["content"]

def get_event_nugget(data):
    return [
        {"nugget" : event["nugget"], "type" : event["type"], "subtype" : event["subtype"], "realis" : event["realis"]}
        for hopper in data["cyberevent"]["hopper"] for event in hopper["events"]
    ]
def get_event_args(data):
    events = [event for hopper in data["cyberevent"]["hopper"] for event in hopper["events"]]
    args = []
    for event in events:
        if "argument" in event.keys():
            args.extend(event["argument"])
    return args

def get_idxs_from_text(text, text_tokenized):
    rest_text = text
    last_idx = 0
    result_dict = []

    for substring in text_tokenized:
        index = rest_text.find(substring)
        result_dict.append(
            {
                "word" : substring,
                "start_idx" : last_idx + index,
                "end_idx" : last_idx + index + len(substring)
            }
        )
        rest_text = rest_text[index + len(substring) : ]
        last_idx += index + len(substring)
    return result_dict

def get_entity_from_idx(start_idx, end_idx, event_nuggets):
    event_nuggets_idxs = [(nugget["nugget"]["startOffset"], nugget["nugget"]["endOffset"]) for nugget in event_nuggets]
    for idx, (nugget_start, nugget_end) in enumerate(event_nuggets_idxs):
        if (start_idx == nugget_start and end_idx == nugget_end) or (start_idx == nugget_start and end_idx <= nugget_end) or (start_idx == nugget_start and end_idx > nugget_end) or (end_idx == nugget_end and start_idx < nugget_start) or (start_idx <= nugget_start and end_idx <= nugget_end and end_idx > nugget_start):
            return "B-" + event_nuggets[idx]["subtype"]
        elif (start_idx > nugget_start and end_idx <= nugget_end) or (start_idx > nugget_start and start_idx < nugget_end):
            return "I-" + event_nuggets[idx]["subtype"]
    return "O"

def get_entity_and_realis_from_idx(start_idx, end_idx, event_nuggets):
    event_nuggets_idxs = [(nugget["nugget"]["startOffset"], nugget["nugget"]["endOffset"]) for nugget in event_nuggets]
    for idx, (nugget_start, nugget_end) in enumerate(event_nuggets_idxs):
        if (start_idx == nugget_start and end_idx == nugget_end) or (start_idx == nugget_start and end_idx <= nugget_end) or (start_idx == nugget_start and end_idx > nugget_end) or (end_idx == nugget_end and start_idx < nugget_start) or (start_idx <= nugget_start and end_idx <= nugget_end and end_idx > nugget_start):
            return "B-" + event_nuggets[idx]["subtype"], "B-" + event_nuggets[idx]["realis"]
        elif (start_idx > nugget_start and end_idx <= nugget_end) or (start_idx > nugget_start and start_idx < nugget_end):
            return "I-" + event_nuggets[idx]["subtype"], "I-" + event_nuggets[idx]["realis"]
    return "O", "O"

def get_args_entity_from_idx(start_idx, end_idx, event_args):
    event_nuggets_idxs = [(nugget["startOffset"], nugget["endOffset"]) for nugget in event_args]
    for idx, (nugget_start, nugget_end) in enumerate(event_nuggets_idxs):
        if (start_idx == nugget_start and end_idx == nugget_end) or (start_idx == nugget_start and end_idx <= nugget_end) or (start_idx == nugget_start and end_idx > nugget_end) or (end_idx == nugget_end and start_idx < nugget_start) or (start_idx <= nugget_start and end_idx <= nugget_end and end_idx > nugget_start):
            return "B-" + event_args[idx]["type"]
        elif (start_idx > nugget_start and end_idx <= nugget_end) or (start_idx > nugget_start and start_idx < nugget_end):
            return "I-" + event_args[idx]["type"]
    return "O"

def split_with_character(string, char):
    result = []
    start = 0
    for i, c in enumerate(string):
        if c == char:
            result.append(string[start:i])
            result.append(char)
            start = i + 1
    result.append(string[start:])
    return [x for x in result if x != '']

def extend_list_with_character(content_list, character):
    content_as_words = []
    for word in content_list:
        if character in word:
            split_list = split_with_character(word, character)
            content_as_words.extend(split_list)
        else:
            content_as_words.append(word)
    return content_as_words

def find_dict_by_overlap(list_of_dicts, key_value_pairs):
    for dictionary in list_of_dicts:
        if max(dictionary["start"], dictionary["end"]) >= min(key_value_pairs["start"], key_value_pairs["end"]) and max(key_value_pairs["start"], key_value_pairs["end"]) >= min(dictionary["start"], dictionary["end"]):
            return dictionary
    return None

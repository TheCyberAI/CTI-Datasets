import xml.etree.ElementTree as ET
import json
import os

def xml_to_raw_list(xml_file, output_file):
    # Check if file exists
    if not os.path.exists(xml_file):
        print(f"Error: The file '{xml_file}' was not found.")
        return

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        print(f"Error parsing XML: {e}")
        return

    count = 0
    with open(output_file, 'w', encoding='utf-8') as outfile:
        # Iterate through each Event in the dataset
        for event in root.findall('Event'):
            
            # --- 1. Create the 'human' prompt ---
            report_info = event.find('info').text if event.find('info') is not None else "Unknown Report"
            date = event.find('date').text if event.find('date') is not None else "Unknown Date"
            
            human_value = (
                f"I need the Indicators of Compromise (IOCs) associated with the report "
                f"'{report_info}' from {date}. Please list them by type."
            )

            # --- 2. Create the 'gpt' response ---
            attributes = event.find('Attribute')
            ioc_data = {
                "MD5 Hashes": [],
                "URLs": [],
                "IP Addresses": [],
                "Filenames": [],
                "Emails": [],
                "Vulnerabilities": []
            }

            if attributes is not None:
                for item in attributes.findall('item'):
                    itype = item.find('type').text if item.find('type') is not None else ""
                    value = item.find('value').text if item.find('value') is not None else ""
                    
                    if not value: continue

                    if itype == 'md5':
                        ioc_data['MD5 Hashes'].append(value)
                    elif itype == 'url':
                        ioc_data['URLs'].append(value)
                    elif itype == 'ip-src':
                        ioc_data['IP Addresses'].append(value)
                    elif itype == 'filename':
                        ioc_data['Filenames'].append(value)
                    elif 'email' in itype:
                        ioc_data['Emails'].append(value)
                    elif itype == 'vulnerability':
                        ioc_data['Vulnerabilities'].append(value)

            # Build the response string
            response_lines = []
            for category, items in ioc_data.items():
                if items:
                    response_lines.append(f"### {category}")
                    for i in items:
                        response_lines.append(f"- {i}")
            
            if not response_lines:
                gpt_value = "No specific indicators of compromise were found listed in this report event."
            else:
                gpt_value = "Here are the extracted IOCs for that report:\n\n" + "\n".join(response_lines)

            # --- 3. Construct the List Object (No "conversations" key) ---
            # This creates a direct list: [ {Human}, {GPT} ]
            conversation_list = [
                {
                    "from": "human",
                    "value": human_value
                },
                {
                    "from": "gpt",
                    "value": gpt_value
                }
            ]

            # Write the list directly to the line
            outfile.write(json.dumps(conversation_list) + '\n')
            count += 1

    print(f"Conversion complete. {count} lines saved to {output_file}")

if __name__ == "__main__":
    xml_to_raw_list('CTIDataset_2014_MalwareEvent.xml', 'custom_sharegpt_dataset.jsonl')

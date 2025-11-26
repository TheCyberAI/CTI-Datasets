import xml.etree.ElementTree as ET
import json
import os

def xml_to_sharegpt(xml_file, output_file):
    # Check if file exists before trying to parse
    if not os.path.exists(xml_file):
        print(f"Error: The file '{xml_file}' was not found in the current directory.")
        return

    # Parse the XML file
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
            # We use the info/date tags to create a realistic request
            report_info = event.find('info').text if event.find('info') is not None else "Unknown Report"
            date = event.find('date').text if event.find('date') is not None else "Unknown Date"
            
            human_value = (
                f"I need the Indicators of Compromise (IOCs) associated with the report "
                f"'{report_info}' from {date}. Please list them by type."
            )

            # --- 2. Create the 'gpt' response ---
            # We extract attributes and group them to create the answer
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
                    # Safe extraction of text in case tags are empty
                    itype = item.find('type').text if item.find('type') is not None else ""
                    value = item.find('value').text if item.find('value') is not None else ""
                    
                    if not value: continue

                    # Sort data into categories for a clean response
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

            # Build a readable string response from the extracted data
            response_lines = []
            for category, items in ioc_data.items():
                if items: # Only add categories that have data
                    response_lines.append(f"### {category}")
                    for i in items:
                        response_lines.append(f"- {i}")
            
            # If no attributes were found, provide a fallback response
            if not response_lines:
                gpt_value = "No specific indicators of compromise were found listed in this report event."
            else:
                gpt_value = "Here are the extracted IOCs for that report:\n\n" + "\n".join(response_lines)

            # --- 3. Construct the ShareGPT Object ---
            sharegpt_entry = {
                "conversations": [
                    {
                        "from": "human",
                        "value": human_value
                    },
                    {
                        "from": "gpt",
                        "value": gpt_value
                    }
                ]
            }

            # Write the single line JSON object
            outfile.write(json.dumps(sharegpt_entry) + '\n')
            count += 1

    print(f"Conversion complete. {count} conversation pairs saved to {output_file}")

# Run the function with the updated filename
if __name__ == "__main__":
    xml_to_sharegpt('CTIDataset_2014_MalwareEvent.xml', 'sharegpt_dataset.jsonl')

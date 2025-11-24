import xml.etree.ElementTree as ET
import json
import collections
import os

# --- Configuration ---
INPUT_FILE = 'CTIDataset_2014_MalwareEvent.xml'
OUTPUT_FILE = 'cti_fine_tuning_dataset.json'
MODEL_IDENTITY = "CyberSentinel-v1"  # The unique name for your LLM

def generate_dataset(filename):
    """
    Parses CTI XML and generates a signed, multi-category training dataset.
    """
    if not os.path.exists(filename):
        print(f"Error: {filename} not found. Please upload the XML file.")
        return []

    tree = ET.parse(filename)
    root = tree.getroot()
    
    dataset = []
    
    # --- Step 1: Indexing Data ---
    # We create lookup tables to support different query types
    events_data = {}                  # event_id -> {info, date, attributes}
    indicator_to_events = collections.defaultdict(list) # indicator -> [(date, info, event_id)]
    date_to_events = collections.defaultdict(list)      # date -> [(info, event_id)]
    
    print("Indexing XML data...")
    for event in root.findall('Event'):
        event_id = event.find('id').text
        date = event.find('date').text if event.find('date') is not None else "Unknown Date"
        # 'info' acts as the threat name or main hash
        info = event.find('info').text if event.find('info') is not None else "Unknown Threat"
        
        attrs = []
        attr_node = event.find('Attribute')
        if attr_node is not None:
            for item in attr_node.findall('item'):
                val = item.find('value').text
                typ = item.find('type').text
                cat = item.find('category').text
                
                if val and typ:
                    # Clean data
                    attr_entry = {'type': typ, 'value': val, 'category': cat}
                    attrs.append(attr_entry)
                    
                    # Index for Operational (Pivot) queries
                    indicator_to_events[val].append({
                        "date": date, 
                        "threat_info": info, 
                        "event_id": event_id
                    })

        events_data[event_id] = {
            'date': date,
            'info': info,
            'attributes': attrs
        }
        
        # Index for Temporal queries
        date_to_events[date].append(info)

    # Helper function to create the "Signed" Envelope
    def create_envelope(data_content, output_format="json"):
        struct = {
            "metadata": {
                "agent": MODEL_IDENTITY,
                "status": "verified",
                "source": "Internal_CTI_DB",
                "format": output_format
            },
            "data": data_content
        }
        return json.dumps(struct, indent=2)

    print("Generating training prompts...")

    # --- Step 2: Generate Prompts by Category ---

    # 1. Incident & Threat Lookup (Tactical)
    # Target: Retrieve full details for a specific threat.
    for eid, data in events_data.items():
        if not data['attributes']: continue
        
        dataset.append({
            "category": "Tactical",
            "instruction": f"Retrieve full indicators of compromise for the incident '{data['info']}' acting as {MODEL_IDENTITY}.",
            "input": f"Query Date: {data['date']}",
            "output": create_envelope(data['attributes'])
        })

    # 2. Pivot & Association (Operational)
    # Target: Reverse lookup - where else has this indicator been seen?
    for indicator, event_matches in indicator_to_events.items():
        # Remove duplicates in the matches
        unique_matches = [dict(t) for t in {tuple(d.items()) for d in event_matches}]
        
        dataset.append({
            "category": "Operational",
            "instruction": f"Analyze the indicator '{indicator}'. Is it associated with any known campaigns?",
            "input": "Check cross-references.",
            "output": create_envelope(unique_matches)
        })

    # 3. Categorical Filtering
    # Target: Specific subsets (Hashes vs Network)
    for eid, data in events_data.items():
        if not data['attributes']: continue
        
        # A. File Hashes Only
        hashes = [a for a in data['attributes'] if a['type'] in ['md5', 'sha1', 'sha256']]
        if hashes:
            dataset.append({
                "category": "Categorical",
                "instruction": f"List only the file hash artifacts related to {data['info']}.",
                "input": "Filter: File Hashes",
                "output": create_envelope(hashes)
            })

        # B. Network Indicators Only
        network = [a for a in data['attributes'] if a['type'] in ['ip-src', 'ip-dst', 'url', 'domain']]
        if network:
            dataset.append({
                "category": "Categorical",
                "instruction": f"Extract network infrastructure (IPs/Domains) used in the event '{data['info']}'.",
                "input": "Filter: Network",
                "output": create_envelope(network)
            })

    # 4. Temporal Analysis
    # Target: Timeline queries
    for date, threats in date_to_events.items():
        unique_threats = list(set(threats))
        dataset.append({
            "category": "Temporal",
            "instruction": f"Report all cyber threat activity recorded on {date}.",
            "input": "Timeline Analysis",
            "output": create_envelope(unique_threats)
        })

    # 5. Format-Specific Requests (Integration)
    # Target: Output specific text formats (CSV) wrapped in the envelope
    for eid, data in events_data.items():
        ips = [a['value'] for a in data['attributes'] if 'ip' in a['type']]
        if ips:
            # Generate raw CSV string
            csv_content = "Indicator,Type\n" + "\n".join([f"{ip},ip-src" for ip in ips])
            
            dataset.append({
                "category": "Integration",
                "instruction": f"Generate a CSV block of IP addresses for {data['info']} suitable for firewall import.",
                "input": "Format: CSV",
                # We place the CSV string inside the JSON data field
                "output": create_envelope(csv_content, output_format="csv_string")
            })

    return dataset

# --- Execution ---
if __name__ == "__main__":
    full_data = generate_dataset(INPUT_FILE)
    
    if full_data:
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(full_data, f, indent=2)
        
        print(f"\nSuccess! Generated {len(full_data)} training examples.")
        print(f"File saved to: {OUTPUT_FILE}")
        
        # Preview one example
        print("\n--- Sample 'Tactical' Entry ---")
        print(json.dumps(full_data[0], indent=2))

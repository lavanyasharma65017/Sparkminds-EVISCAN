#!/usr/bin/env python3
"""
Script to create realistic, coherent stories for UFDR case files.
Replaces generic synthetic messages with case-specific narratives.
"""

import json
import random
from pathlib import Path
from datetime import datetime, timedelta

# Base directory
BASE_DIR = Path(__file__).parent / "data" / "UFDR's(new)"

# Case-specific message templates and storylines
CASE_STORIES = {
    "case 1 Kidnapping Conspiracy": {
        "case_type": "Kidnapping Conspiracy",
        "main_suspect": "Rajesh Kumar",
        "accomplice": "Priya Sharma",
        "victim_name": "Amit Patel",
        "messages": [
            ("Rajesh", "Priya", "The target is confirmed. He'll be at the mall tomorrow at 3 PM. Are you ready?"),
            ("Priya", "Rajesh", "Yes, I have the van ready. What about the location?"),
            ("Rajesh", "Priya", "Warehouse on the outskirts. No one goes there. Perfect spot."),
            ("Priya", "Rajesh", "What about payment? When do we get the money?"),
            ("Rajesh", "Priya", "Half now, half after delivery. I'll transfer 50k today."),
            ("Rajesh", "Priya", "Remember, no phones during the operation. Use the burner."),
            ("Priya", "Rajesh", "Got it. I'll be at the location at 2:30 PM sharp."),
            ("Rajesh", "Priya", "Good. Make sure he doesn't see your face. Wear the mask."),
            ("Priya", "Rajesh", "Done. Everything is set. See you tomorrow."),
            ("Rajesh", "Priya", "One more thing - delete all these messages after we're done."),
        ],
        "calls": [
            ("Rajesh", "Priya", 120, "outgoing"),
            ("Priya", "Rajesh", 89, "incoming"),
            ("Rajesh", "Priya", 234, "outgoing"),
        ]
    },
    "case 2 Human Trafficking": {
        "case_type": "Human Trafficking",
        "main_suspect": "Deepak Malhotra",
        "accomplice": "Sneha Verma",
        "messages": [
            ("Deepak", "Sneha", "New batch arrived. 5 girls, ages 18-22. All healthy."),
            ("Sneha", "Deepak", "Good. Where are they now?"),
            ("Deepak", "Sneha", "Safe house in Sector 7. Need to move them by Friday."),
            ("Sneha", "Deepak", "Buyers confirmed? What's the price?"),
            ("Deepak", "Sneha", "2 buyers confirmed. 3L per person. Total 15L."),
            ("Sneha", "Deepak", "When is the transfer happening?"),
            ("Deepak", "Sneha", "Tomorrow night. Meet at the usual place. Bring the documents."),
            ("Sneha", "Deepak", "Documents ready. Passports and IDs prepared."),
            ("Deepak", "Sneha", "Perfect. Make sure they don't talk to anyone. Keep them isolated."),
            ("Sneha", "Deepak", "Understood. They're locked in separate rooms. No phones."),
        ],
        "calls": [
            ("Deepak", "Sneha", 180, "outgoing"),
            ("Sneha", "Deepak", 145, "incoming"),
            ("Deepak", "Sneha", 267, "outgoing"),
        ]
    },
    "case 3 Cyber Fraud  Phishing": {
        "case_type": "Cyber Fraud - Phishing",
        "main_suspect": "Vikram Singh",
        "accomplice": "Anjali Mehta",
        "messages": [
            ("Vikram", "Anjali", "New phishing site is live. Looks exactly like the bank website."),
            ("Anjali", "Vikram", "How many targets have we sent the link to?"),
            ("Vikram", "Anjali", "500 emails sent. Already got 12 responses with login details."),
            ("Anjali", "Vikram", "Great! Transfer the money quickly before they realize."),
            ("Vikram", "Anjali", "Already done. 2.5L transferred to our account. More coming."),
            ("Anjali", "Vikram", "Change the account details. Don't use the same one twice."),
            ("Vikram", "Anjali", "Already switched. Using 3 different accounts now."),
            ("Anjali", "Vikram", "Good. Keep the site running for 2 more days then shut it down."),
            ("Vikram", "Anjali", "Will do. Should we target credit cards next?"),
            ("Anjali", "Vikram", "Yes, but use a different method. OTP scams work better."),
        ],
        "calls": [
            ("Vikram", "Anjali", 95, "outgoing"),
            ("Anjali", "Vikram", 156, "incoming"),
            ("Vikram", "Anjali", 203, "outgoing"),
        ]
    },
    "case 4 Illegal Surveillance": {
        "case_type": "Illegal Surveillance",
        "main_suspect": "Rohit Kapoor",
        "accomplice": "Meera Desai",
        "target": "Business Rival",
        "messages": [
            ("Rohit", "Meera", "Camera installed in his office. Can see everything on his computer."),
            ("Meera", "Rohit", "What about his phone? Can we access his messages?"),
            ("Rohit", "Meera", "Yes, spyware installed. Getting all WhatsApp and SMS."),
            ("Meera", "Rohit", "Perfect. What information have we gathered so far?"),
            ("Rohit", "Meera", "Got his business plans, client list, and financial details."),
            ("Meera", "Rohit", "Excellent. Send me the files. I'll use them in the meeting."),
            ("Rohit", "Meera", "Sending now. Make sure to delete after you use them."),
            ("Meera", "Rohit", "Will do. What about his personal conversations?"),
            ("Rohit", "Meera", "Recording everything. Found some compromising information."),
            ("Meera", "Rohit", "Good. We can use that as leverage if needed."),
        ],
        "calls": [
            ("Rohit", "Meera", 178, "outgoing"),
            ("Meera", "Rohit", 134, "incoming"),
            ("Rohit", "Meera", 245, "outgoing"),
        ]
    },
    "case 5 Domestic Violence Evidence": {
        "case_type": "Domestic Violence Evidence",
        "main_suspect": "Arjun Mehta",
        "victim": "Wife",
        "messages": [
            ("Arjun", "Wife", "Where are you? Come home right now!"),
            ("Wife", "Arjun", "I'm at my mother's place. I need some time."),
            ("Arjun", "Wife", "You can't just leave like that. Get back here immediately."),
            ("Wife", "Arjun", "I'm scared. Please don't hurt me again."),
            ("Arjun", "Wife", "I won't. Just come back. We can talk."),
            ("Wife", "Arjun", "I don't believe you. Last time you said the same thing."),
            ("Arjun", "Wife", "This time is different. I promise. Just come home."),
            ("Wife", "Arjun", "I need to think. Please give me space."),
            ("Arjun", "Wife", "You're making me angry. Don't test my patience."),
            ("Wife", "Arjun", "I'm calling the police if you don't leave me alone."),
        ],
        "calls": [
            ("Arjun", "Wife", 45, "outgoing"),
            ("Arjun", "Wife", 0, "missed"),
            ("Arjun", "Wife", 23, "outgoing"),
        ]
    },
    "case 6 Smuggling Operations": {
        "case_type": "Smuggling Operations",
        "main_suspect": "Karan Malhotra",
        "accomplice": "Neha Gupta",
        "messages": [
            ("Karan", "Neha", "Shipment arrived at port. Customs cleared. Ready for pickup."),
            ("Neha", "Karan", "How many units? What's the value?"),
            ("Karan", "Neha", "500 units. Market value 50L. We're getting it for 20L."),
            ("Neha", "Karan", "Good profit margin. When can we pick it up?"),
            ("Karan", "Neha", "Tomorrow night. Use the warehouse entrance. No one will see."),
            ("Neha", "Karan", "What about the payment? Cash or transfer?"),
            ("Karan", "Neha", "Half cash, half crypto. Safer that way."),
            ("Neha", "Karan", "Agreed. I'll bring the cash. You handle the crypto transfer."),
            ("Karan", "Neha", "Perfect. Remember, don't tell anyone about this."),
            ("Neha", "Karan", "Understood. This stays between us. See you tomorrow."),
        ],
        "calls": [
            ("Karan", "Neha", 167, "outgoing"),
            ("Neha", "Karan", 198, "incoming"),
            ("Karan", "Neha", 223, "outgoing"),
        ]
    }
}

def generate_realistic_messages(case_name, case_story, base_date, num_messages=30):
    """Generate realistic messages for a case"""
    messages = []
    story_messages = case_story["messages"]
    
    # Add story messages with proper timestamps
    for i, (sender, receiver, text) in enumerate(story_messages):
        msg_date = base_date + timedelta(days=i//3, hours=i%3*2)
        messages.append({
            "from": sender,
            "to": receiver,
            "timestamp": msg_date.strftime("%Y-%m-%dT%H:%M:%S"),
            "text": text
        })
    
    # Add some filler messages to reach num_messages
    filler_phrases = [
        "Call me when you're free",
        "Did you get my message?",
        "We need to meet",
        "Check your email",
        "Everything is ready",
        "See you soon",
        "Keep it confidential",
        "Delete this message",
        "We'll discuss later",
        "Stay in touch"
    ]
    
    remaining = num_messages - len(messages)
    for i in range(remaining):
        sender = random.choice([case_story.get("main_suspect", "Unknown"), 
                               case_story.get("accomplice", "Unknown")])
        receiver = random.choice([case_story.get("accomplice", "Unknown"),
                                 case_story.get("main_suspect", "Unknown")])
        text = random.choice(filler_phrases)
        msg_date = base_date + timedelta(days=random.randint(0, 10), 
                                        hours=random.randint(8, 22))
        messages.append({
            "from": sender,
            "to": receiver,
            "timestamp": msg_date.strftime("%Y-%m-%dT%H:%M:%S"),
            "text": text
        })
    
    # Sort by timestamp
    messages.sort(key=lambda x: x["timestamp"])
    return messages

def generate_realistic_calls(case_name, case_story, base_date, num_calls=25):
    """Generate realistic call logs for a case"""
    calls = []
    story_calls = case_story.get("calls", [])
    
    # Add story calls
    for i, (caller, receiver, duration, call_type) in enumerate(story_calls):
        call_date = base_date + timedelta(days=i//2, hours=i%2*3)
        calls.append({
            "from": caller,
            "to": receiver,
            "timestamp": call_date.strftime("%Y-%m-%dT%H:%M:%S"),
            "duration": duration,
            "type": call_type
        })
    
    # Add filler calls
    remaining = num_calls - len(calls)
    for i in range(remaining):
        caller = random.choice([case_story.get("main_suspect", "Unknown"),
                               case_story.get("accomplice", "Unknown")])
        receiver = random.choice([case_story.get("accomplice", "Unknown"),
                                 case_story.get("main_suspect", "Unknown")])
        duration = random.randint(30, 600)
        call_type = random.choice(["incoming", "outgoing", "missed"])
        call_date = base_date + timedelta(days=random.randint(0, 10),
                                         hours=random.randint(8, 22))
        calls.append({
            "from": caller,
            "to": receiver,
            "timestamp": call_date.strftime("%Y-%m-%dT%H:%M:%S"),
            "duration": duration,
            "type": call_type
        })
    
    # Sort by timestamp
    calls.sort(key=lambda x: x["timestamp"])
    return calls

def update_contacts(case_name, case_story):
    """Update contacts to match the story"""
    contacts = []
    
    # Add main characters
    if "main_suspect" in case_story:
        contacts.append({
            "name": case_story["main_suspect"],
            "phone": "+919876543210",
            "relationship": "Primary Contact",
            "last_contact": "2025-11-20T10:00:00"
        })
    
    if "accomplice" in case_story:
        contacts.append({
            "name": case_story["accomplice"],
            "phone": "+919123456789",
            "relationship": "Associate",
            "last_contact": "2025-11-20T10:00:00"
        })
    
    if "victim" in case_story:
        contacts.append({
            "name": case_story.get("victim_name", case_story["victim"]),
            "phone": "+919555443322",
            "relationship": "Victim",
            "last_contact": "2025-11-20T10:00:00"
        })
    
    return contacts

def main():
    """Main function to update all case files with realistic stories"""
    print("Creating realistic stories for UFDR cases...\n")
    
    if not BASE_DIR.exists():
        print(f"Error: Base directory {BASE_DIR} does not exist!")
        return
    
    base_date = datetime(2025, 11, 10, 10, 0, 0)
    
    for case_name, case_story in CASE_STORIES.items():
        case_dir = BASE_DIR / case_name
        if not case_dir.exists():
            print(f"Skipping {case_name} - directory not found")
            continue
        
        print(f"Processing: {case_name}")
        
        # Update SMS messages
        sms_file = case_dir / "Artifacts" / "SMS" / "sms.json"
        if sms_file.exists():
            messages = generate_realistic_messages(case_name, case_story, base_date, 30)
            with open(sms_file, 'w', encoding='utf-8') as f:
                json.dump(messages, f, indent=2, ensure_ascii=False)
            print(f"  [OK] Updated SMS messages ({len(messages)} messages)")
        
        # Update WhatsApp messages
        whatsapp_file = case_dir / "Artifacts" / "WhatsApp" / "whatsapp.json"
        if whatsapp_file.exists():
            messages = generate_realistic_messages(case_name, case_story, base_date, 30)
            with open(whatsapp_file, 'w', encoding='utf-8') as f:
                json.dump(messages, f, indent=2, ensure_ascii=False)
            print(f"  [OK] Updated WhatsApp messages ({len(messages)} messages)")
        
        # Update Calls
        calls_file = case_dir / "Artifacts" / "Calls" / "calls.json"
        if calls_file.exists():
            calls = generate_realistic_calls(case_name, case_story, base_date, 25)
            with open(calls_file, 'w', encoding='utf-8') as f:
                json.dump(calls, f, indent=2, ensure_ascii=False)
            print(f"  [OK] Updated call logs ({len(calls)} calls)")
        
        # Update Contacts
        contacts_file = case_dir / "Artifacts" / "Contacts" / "contacts.json"
        if contacts_file.exists():
            contacts = update_contacts(case_name, case_story)
            # Keep some existing contacts and add story contacts
            try:
                with open(contacts_file, 'r', encoding='utf-8') as f:
                    existing_contacts = json.load(f)
                # Merge, keeping story contacts first
                all_contacts = contacts + existing_contacts[:10]  # Keep first 10 existing
            except:
                all_contacts = contacts
            
            with open(contacts_file, 'w', encoding='utf-8') as f:
                json.dump(all_contacts, f, indent=2, ensure_ascii=False)
            print(f"  [OK] Updated contacts ({len(all_contacts)} contacts)")
        
        # Update case_info.json with better description
        case_info_file = case_dir / "__metadata__" / "case_info.json"
        if case_info_file.exists():
            try:
                with open(case_info_file, 'r', encoding='utf-8') as f:
                    case_info = json.load(f)
                
                # Update description with story context
                if case_name == "case 1 Kidnapping Conspiracy":
                    case_info["description"] = "Investigation into kidnapping conspiracy. Suspect Rajesh Kumar coordinated with accomplice Priya Sharma to abduct victim Amit Patel. Evidence shows planning conversations, location scouting, and payment arrangements."
                    case_info["suspects"] = [
                        {"name": "Rajesh Kumar", "role": "Primary Suspect", "status": "Under Investigation", "device_owner": True},
                        {"name": "Priya Sharma", "role": "Accomplice", "status": "Under Investigation", "phone": "+919123456789"}
                    ]
                elif case_name == "case 2 Human Trafficking":
                    case_info["description"] = "Investigation into human trafficking operations. Suspect Deepak Malhotra coordinated with Sneha Verma to traffic young women. Evidence shows discussions about victims, buyers, pricing, and document forgery."
                    case_info["suspects"] = [
                        {"name": "Deepak Malhotra", "role": "Primary Suspect", "status": "Under Investigation", "device_owner": True},
                        {"name": "Sneha Verma", "role": "Accomplice", "status": "Under Investigation", "phone": "+919123456789"}
                    ]
                elif case_name == "case 3 Cyber Fraud  Phishing":
                    case_info["description"] = "Investigation into cyber fraud and phishing operations. Suspect Vikram Singh created fake banking websites with accomplice Anjali Mehta to steal login credentials and transfer funds illegally."
                    case_info["suspects"] = [
                        {"name": "Vikram Singh", "role": "Primary Suspect", "status": "Under Investigation", "device_owner": True},
                        {"name": "Anjali Mehta", "role": "Accomplice", "status": "Under Investigation", "phone": "+919123456789"}
                    ]
                elif case_name == "case 4 Illegal Surveillance":
                    case_info["description"] = "Investigation into illegal surveillance operations. Suspect Rohit Kapoor installed cameras and spyware to monitor a business rival's activities, accessing confidential business information and personal communications."
                    case_info["suspects"] = [
                        {"name": "Rohit Kapoor", "role": "Primary Suspect", "status": "Under Investigation", "device_owner": True},
                        {"name": "Meera Desai", "role": "Accomplice", "status": "Under Investigation", "phone": "+919123456789"}
                    ]
                elif case_name == "case 5 Domestic Violence Evidence":
                    case_info["description"] = "Investigation into domestic violence case. Evidence shows suspect Arjun Mehta engaged in threatening and abusive communications with his wife, including demands to return home and threats of violence."
                    case_info["suspects"] = [
                        {"name": "Arjun Mehta", "role": "Primary Suspect", "status": "Under Investigation", "device_owner": True}
                    ]
                elif case_name == "case 6 Smuggling Operations":
                    case_info["description"] = "Investigation into smuggling operations. Suspect Karan Malhotra coordinated with Neha Gupta to smuggle contraband goods through ports, involving customs clearance, warehouse storage, and illegal distribution."
                    case_info["suspects"] = [
                        {"name": "Karan Malhotra", "role": "Primary Suspect", "status": "Under Investigation", "device_owner": True},
                        {"name": "Neha Gupta", "role": "Accomplice", "status": "Under Investigation", "phone": "+919123456789"}
                    ]
                
                with open(case_info_file, 'w', encoding='utf-8') as f:
                    json.dump(case_info, f, indent=2, ensure_ascii=False)
                print(f"  [OK] Updated case_info.json")
            except Exception as e:
                print(f"  [ERROR] Failed to update case_info.json: {e}")
        
        print()
    
    print("[OK] Story creation complete!")

if __name__ == "__main__":
    main()


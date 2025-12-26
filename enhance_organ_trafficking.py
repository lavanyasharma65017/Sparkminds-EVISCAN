#!/usr/bin/env python3
"""
Script to enhance UFDR_FILE.format with realistic organ trafficking story
involving a doctor, with proper medical terminology and real names.
"""

import json
import random
from pathlib import Path
from datetime import datetime, timedelta

# Base directory
CASE_DIR = Path(__file__).parent / "data" / "UFDR's(new)" / "UFDR_FILE.format"

# Organ trafficking story with realistic medical conversations
ORGAN_TRAFFICKING_STORY = {
    "main_suspect": "Dr. Arjun Mehta",
    "main_phone": "+919988776655",
    "characters": {
        "broker": {
            "name": "Sahil Kapoor",
            "phone": "+919911223344",
            "role": "Organ Broker"
        },
        "anesthesiologist": {
            "name": "Dr. Priya Sharma",
            "phone": "+919876543210",
            "role": "Anesthesiologist"
        },
        "nurse": {
            "name": "Ravi Kumar",
            "phone": "+919123456789",
            "role": "OR Nurse"
        },
        "buyer_agent": {
            "name": "Vikram Singh",
            "phone": "+919555443322",
            "role": "Buyer's Agent"
        },
        "clinic_manager": {
            "name": "Amit Verma",
            "phone": "+919444332211",
            "role": "Clinic Manager"
        },
        "lab_tech": {
            "name": "Neha Patel",
            "phone": "+919333221100",
            "role": "Lab Technician"
        }
    },
    "conversations": [
        # Initial contact and planning
        ("Dr. Arjun Mehta", "Sahil Kapoor", "Sahil, I have a potential donor. 28-year-old male, O-positive. Healthy. When can we schedule the procedure?"),
        ("Sahil Kapoor", "Dr. Arjun Mehta", "Dr. Mehta, excellent. I have a buyer ready. They need a kidney. Price is 15 lakhs. When can you do it?"),
        ("Dr. Arjun Mehta", "Sahil Kapoor", "This weekend. Saturday night at the private clinic. Make sure the donor is prepped and ready by 10 PM."),
        ("Sahil Kapoor", "Dr. Arjun Mehta", "Done. I'll arrange transport. What about the recipient? They're flying in from Dubai."),
        ("Dr. Arjun Mehta", "Sahil Kapoor", "Good. Have them at the clinic by 11 PM. I'll need Dr. Priya for anesthesia. She's reliable."),
        
        # Medical coordination
        ("Dr. Arjun Mehta", "Dr. Priya Sharma", "Priya, I need you this Saturday night. Private procedure at the clinic. Can you make it?"),
        ("Dr. Priya Sharma", "Dr. Arjun Mehta", "Arjun, what kind of procedure? I need to know what I'm getting into."),
        ("Dr. Arjun Mehta", "Dr. Priya Sharma", "Nephrectomy. Donor procedure. Standard protocol. You'll be well compensated."),
        ("Dr. Priya Sharma", "Dr. Arjun Mehta", "Fine. What time? And make sure all equipment is ready. I don't want complications."),
        ("Dr. Arjun Mehta", "Dr. Priya Sharma", "10 PM sharp. Ravi will have everything ready. This is urgent."),
        
        # Nurse coordination
        ("Dr. Arjun Mehta", "Ravi Kumar", "Ravi, prepare OR 3 for Saturday night. Full nephrectomy setup. Keep it quiet."),
        ("Ravi Kumar", "Dr. Arjun Mehta", "Sir, I'll have everything ready. Instruments sterilized. What about the donor?"),
        ("Dr. Arjun Mehta", "Ravi Kumar", "Donor will arrive at 9:30 PM. Pre-op by 10 PM. Make sure no one else is in the clinic."),
        ("Ravi Kumar", "Dr. Arjun Mehta", "Understood. I'll clear the schedule. What about post-op care?"),
        ("Dr. Arjun Mehta", "Ravi Kumar", "Standard recovery. 24 hours observation. Then discharge. No records."),
        
        # Buyer coordination
        ("Sahil Kapoor", "Vikram Singh", "Vikram, the procedure is confirmed. Saturday 11 PM. Your client needs to be ready."),
        ("Vikram Singh", "Sahil Kapoor", "My client is ready. They've transferred 10 lakhs advance. Rest after procedure."),
        ("Sahil Kapoor", "Vikram Singh", "Good. Make sure they have all travel documents. This needs to be quick and clean."),
        ("Vikram Singh", "Sahil Kapoor", "Everything is arranged. They'll leave immediately after. No questions asked."),
        
        # Lab work
        ("Dr. Arjun Mehta", "Neha Patel", "Neha, I need blood work done. O-positive donor. Full panel. Results by Friday."),
        ("Neha Patel", "Dr. Arjun Mehta", "Dr. Mehta, I'll run the tests. What about tissue typing? Do you need HLA matching?"),
        ("Dr. Arjun Mehta", "Neha Patel", "Yes, full HLA panel. Cross-match with recipient. Make sure everything is compatible."),
        ("Neha Patel", "Dr. Arjun Mehta", "I'll have results by Friday evening. I'll send them directly to you."),
        
        # Payment discussions
        ("Sahil Kapoor", "Dr. Arjun Mehta", "Dr. Mehta, payment structure: 15L total. 5L to you, 3L to Priya, 2L to Ravi, rest to me. Agreed?"),
        ("Dr. Arjun Mehta", "Sahil Kapoor", "Agreed. But I want my share in crypto. Safer that way. Bank transfer is too risky."),
        ("Sahil Kapoor", "Dr. Arjun Mehta", "Crypto works. I'll transfer after procedure is complete and recipient is stable."),
        
        # Pre-procedure
        ("Dr. Arjun Mehta", "Amit Verma", "Amit, clear the clinic this Saturday night. No other procedures. No staff except our team."),
        ("Amit Verma", "Dr. Arjun Mehta", "Done. I've cancelled all appointments. Security will be informed. What about cameras?"),
        ("Dr. Arjun Mehta", "Amit Verma", "Disable all cameras. All recordings. This never happened. Understood?"),
        ("Amit Verma", "Dr. Arjun Mehta", "Understood. Everything will be clean. No traces."),
        
        # Day of procedure
        ("Sahil Kapoor", "Dr. Arjun Mehta", "Dr. Mehta, donor is on the way. ETA 9:30 PM. Everything ready?"),
        ("Dr. Arjun Mehta", "Sahil Kapoor", "Yes, OR is prepped. Team is ready. Make sure donor is sedated before arrival."),
        ("Sahil Kapoor", "Dr. Arjun Mehta", "Already done. He won't remember anything. Clean extraction."),
        
        # During procedure
        ("Dr. Arjun Mehta", "Dr. Priya Sharma", "Priya, start general anesthesia. We're beginning in 10 minutes."),
        ("Dr. Priya Sharma", "Dr. Arjun Mehta", "Anesthesia started. Patient is stable. Vitals normal. Proceed when ready."),
        ("Dr. Arjun Mehta", "Ravi Kumar", "Ravi, hand me the scalpel. Make incision at marked location."),
        
        # Post-procedure
        ("Dr. Arjun Mehta", "Sahil Kapoor", "Procedure complete. Organ is viable. Recipient can proceed. Payment now."),
        ("Sahil Kapoor", "Dr. Arjun Mehta", "Excellent. Crypto transfer initiated. You'll receive confirmation in 30 minutes."),
        ("Dr. Arjun Mehta", "Ravi Kumar", "Ravi, clean everything. Dispose of all materials properly. No evidence."),
        ("Ravi Kumar", "Dr. Arjun Mehta", "Done. All instruments sterilized. Records deleted. Clean as requested."),
        
        # Follow-up
        ("Vikram Singh", "Sahil Kapoor", "Recipient is stable. Procedure successful. They're very satisfied. More business coming."),
        ("Sahil Kapoor", "Dr. Arjun Mehta", "Dr. Mehta, client is happy. They want another procedure next month. Interested?"),
        ("Dr. Arjun Mehta", "Sahil Kapoor", "Yes, but we need to be more careful. Last one was too risky. Better security."),
        
        # Cover-up discussions
        ("Dr. Arjun Mehta", "Amit Verma", "Amit, make sure all patient records are deleted. This was never in our system."),
        ("Amit Verma", "Dr. Arjun Mehta", "All records purged. Database cleaned. No trace of Saturday's procedure."),
        ("Dr. Arjun Mehta", "Dr. Priya Sharma", "Priya, remember - this was a standard nephrectomy for a registered patient. Nothing unusual."),
        ("Dr. Priya Sharma", "Dr. Arjun Mehta", "Understood. Standard procedure. Nothing to report. All documentation is in order."),
    ],
    "calls": [
        ("Dr. Arjun Mehta", "Sahil Kapoor", 234, "outgoing"),
        ("Sahil Kapoor", "Dr. Arjun Mehta", 189, "incoming"),
        ("Dr. Arjun Mehta", "Dr. Priya Sharma", 456, "outgoing"),
        ("Dr. Priya Sharma", "Dr. Arjun Mehta", 312, "incoming"),
        ("Dr. Arjun Mehta", "Ravi Kumar", 123, "outgoing"),
        ("Sahil Kapoor", "Vikram Singh", 267, "outgoing"),
        ("Dr. Arjun Mehta", "Neha Patel", 89, "outgoing"),
        ("Dr. Arjun Mehta", "Amit Verma", 178, "outgoing"),
    ]
}

def generate_realistic_messages(base_date, num_messages=3200):
    """Generate realistic organ trafficking messages"""
    messages = []
    story_conversations = ORGAN_TRAFFICKING_STORY["conversations"]
    characters = ORGAN_TRAFFICKING_STORY["characters"]
    
    # Add story conversations with proper timestamps
    for i, (sender, receiver, text) in enumerate(story_conversations):
        msg_date = base_date + timedelta(days=i//5, hours=(i%5)*2 + 8)
        # Convert names to phone numbers
        sender_phone = ORGAN_TRAFFICKING_STORY["main_phone"] if sender == "Dr. Arjun Mehta" else None
        receiver_phone = ORGAN_TRAFFICKING_STORY["main_phone"] if receiver == "Dr. Arjun Mehta" else None
        
        # Check characters dict
        for char_name, char_info in characters.items():
            if char_info["name"] == sender:
                sender_phone = char_info["phone"]
            if char_info["name"] == receiver:
                receiver_phone = char_info["phone"]
        
        # Fallback to main phone if still None
        if sender_phone is None:
            sender_phone = ORGAN_TRAFFICKING_STORY["main_phone"]
        if receiver_phone is None:
            receiver_phone = ORGAN_TRAFFICKING_STORY["main_phone"]
        
        messages.append({
            "from": sender_phone,
            "to": receiver_phone,
            "timestamp": msg_date.strftime("%Y-%m-%dT%H:%M:%S"),
            "text": text
        })
    
    # Add filler messages with medical context and organ trafficking themes
    medical_filler = [
        "Patient is stable. Vitals normal.",
        "Lab results are ready. All parameters within range.",
        "Procedure scheduled. Confirm availability.",
        "Equipment checked. Ready for use.",
        "Anesthesia protocol confirmed.",
        "Post-op care arranged.",
        "Discharge papers ready.",
        "Follow-up appointment scheduled.",
        "Medication prescribed. Patient informed.",
        "All documentation complete.",
        "Transfer to recovery room.",
        "Monitor for 24 hours.",
        "No complications observed.",
        "Patient consent obtained.",
        "Pre-op tests completed.",
        "Donor is ready. Blood type confirmed.",
        "Recipient arrived. Prepping for surgery.",
        "Organ is viable. Proceed with transplant.",
        "Payment received. Transaction complete.",
        "Records deleted. No trace left.",
        "Clinic cleared. No staff present.",
        "Transport arranged. ETA 30 minutes.",
        "Buyer confirmed. Price agreed.",
        "Tissue typing complete. Compatible match.",
        "HLA panel results positive.",
        "Cross-match successful. Proceed.",
        "OR prepped. Instruments sterilized.",
        "Anesthesia started. Patient stable.",
        "Procedure complete. Organ harvested.",
        "Recipient stable. Transplant successful.",
        "Discharge patient. No documentation.",
        "Payment in crypto. Transfer initiated.",
        "Clean up complete. All evidence removed.",
        "Next procedure scheduled. Same protocol.",
        "Donor pool available. 3 candidates ready.",
        "International buyer interested. High price.",
        "Documents forged. Passport ready.",
        "Transport vehicle ready. No tracking.",
        "Security cameras disabled. Proceed.",
        "All staff briefed. Keep quiet.",
    ]
    
    # Get all contact phones for more diverse conversations
    all_phones = [ORGAN_TRAFFICKING_STORY["main_phone"]]
    for char_info in characters.values():
        all_phones.append(char_info["phone"])
    # Add some random phone numbers for additional contacts
    for i in range(50):
        all_phones.append(f"+919{800000000 + i:09d}")
    
    remaining = num_messages - len(messages)
    for i in range(remaining):
        sender_phone = random.choice(all_phones)
        receiver_phone = random.choice([p for p in all_phones if p != sender_phone])
        text = random.choice(medical_filler)
        msg_date = base_date + timedelta(days=random.randint(0, 60), hours=random.randint(6, 23))
        messages.append({
            "from": sender_phone,
            "to": receiver_phone,
            "timestamp": msg_date.strftime("%Y-%m-%dT%H:%M:%S"),
            "text": text
        })
    
    # Sort by timestamp
    messages.sort(key=lambda x: x["timestamp"])
    return messages

def generate_realistic_calls(base_date, num_calls=1100):
    """Generate realistic call logs"""
    calls = []
    story_calls = ORGAN_TRAFFICKING_STORY["calls"]
    characters = ORGAN_TRAFFICKING_STORY["characters"]
    
    # Add story calls
    for i, (caller, receiver, duration, call_type) in enumerate(story_calls):
        call_date = base_date + timedelta(days=i//3, hours=i%3*3 + 10)
        # Convert names to phone numbers
        caller_phone = caller
        receiver_phone = receiver
        for char_name, char_info in characters.items():
            if char_info["name"] == caller:
                caller_phone = char_info["phone"]
            if char_info["name"] == receiver:
                receiver_phone = char_info["phone"]
        if caller == "Dr. Arjun Mehta":
            caller_phone = ORGAN_TRAFFICKING_STORY["main_phone"]
        if receiver == "Dr. Arjun Mehta":
            receiver_phone = ORGAN_TRAFFICKING_STORY["main_phone"]
        
        calls.append({
            "from": caller_phone,
            "to": receiver_phone,
            "timestamp": call_date.strftime("%Y-%m-%dT%H:%M:%S"),
            "duration": duration,
            "type": call_type
        })
    
    # Add filler calls with more diverse phone numbers
    remaining = num_calls - len(calls)
    all_phones = [ORGAN_TRAFFICKING_STORY["main_phone"]]
    for char_info in characters.values():
        all_phones.append(char_info["phone"])
    # Add some random phone numbers for additional contacts
    for i in range(50):
        all_phones.append(f"+919{800000000 + i:09d}")
    
    for i in range(remaining):
        caller_phone = random.choice(all_phones)
        receiver_phone = random.choice([p for p in all_phones if p != caller_phone])
        duration = random.randint(15, 1200)
        call_type = random.choice(["incoming", "outgoing", "missed"])
        call_date = base_date + timedelta(days=random.randint(0, 60), hours=random.randint(6, 23))
        calls.append({
            "from": caller_phone,
            "to": receiver_phone,
            "timestamp": call_date.strftime("%Y-%m-%dT%H:%M:%S"),
            "duration": duration,
            "type": call_type
        })
    
    # Sort by timestamp
    calls.sort(key=lambda x: x["timestamp"])
    return calls

def update_contacts():
    """Update contacts with real names and generate additional contacts"""
    contacts = []
    characters = ORGAN_TRAFFICKING_STORY["characters"]
    
    # Add main suspect
    contacts.append({
        "name": "Dr. Arjun Mehta",
        "phone": ORGAN_TRAFFICKING_STORY["main_phone"],
        "relationship": "Device Owner",
        "last_contact": "2025-11-26T10:00:00",
        "notes": "Primary Suspect - Surgeon"
    })
    
    # Add all story characters
    for char_name, char_info in characters.items():
        contacts.append({
            "name": char_info["name"],
            "phone": char_info["phone"],
            "relationship": char_info["role"],
            "last_contact": "2025-11-25T10:00:00",
            "notes": f"Involved in organ trafficking operation"
        })
    
    # Generate additional contacts related to organ trafficking operation
    # Medical professionals
    medical_names = [
        ("Dr. Vikas Malhotra", "Surgeon", "+919111111111"),
        ("Dr. Anjali Desai", "Nephrologist", "+919222222222"),
        ("Dr. Rajesh Patel", "Urologist", "+919333333333"),
        ("Dr. Meera Singh", "Transplant Surgeon", "+919444444444"),
        ("Dr. Karan Verma", "Cardiologist", "+919555555555"),
        ("Dr. Sneha Kapoor", "Anesthesiologist", "+919666666666"),
        ("Dr. Rahul Sharma", "Pathologist", "+919777777777"),
    ]
    
    # Brokers and middlemen
    broker_names = [
        ("Amit Khanna", "Organ Broker", "+919888888888"),
        ("Rohit Agarwal", "Recruiter", "+919999999999"),
        ("Deepak Joshi", "Transport Coordinator", "+919000000000"),
        ("Nikhil Reddy", "Broker", "+919101010101"),
        ("Prateek Nair", "Middleman", "+919202020202"),
    ]
    
    # Clinic staff
    staff_names = [
        ("Sunita Devi", "OR Nurse", "+919303030303"),
        ("Manoj Kumar", "Lab Assistant", "+919404040404"),
        ("Priyanka Shah", "Recovery Nurse", "+919505050505"),
        ("Anil Gupta", "Security Guard", "+919606060606"),
        ("Kavita Rao", "Admin Staff", "+919707070707"),
    ]
    
    # Buyers and recipients
    buyer_names = [
        ("Vikram Malhotra", "Buyer Agent", "+919808080808"),
        ("Arjun Kapoor", "Recipient Coordinator", "+919909090909"),
        ("Ravi Mehta", "International Buyer", "+919010101010"),
        ("Suresh Patel", "Buyer Representative", "+919121212121"),
    ]
    
    # Donors (victims)
    donor_names = [
        ("Ramesh Kumar", "Donor", "+919232323232"),
        ("Suresh Yadav", "Donor", "+919343434343"),
        ("Mohan Singh", "Donor", "+919454545454"),
        ("Rajesh Verma", "Donor", "+919565656565"),
    ]
    
    all_contacts = medical_names + broker_names + staff_names + buyer_names + donor_names
    
    # Add all additional contacts
    for name, role, phone in all_contacts:
        contacts.append({
            "name": name,
            "phone": phone,
            "relationship": role,
            "last_contact": "2025-11-24T10:00:00",
            "notes": "Related to organ trafficking operation"
        })
    
    # Generate more generic contacts to reach 200
    remaining = 200 - len(contacts)
    for i in range(remaining):
        contact_types = ["Patient", "Supplier", "Contact", "Associate", "Unknown"]
        contacts.append({
            "name": f"Contact_{i+1}",
            "phone": f"+919{800000000 + i:09d}",
            "relationship": random.choice(contact_types),
            "last_contact": "2025-11-23T10:00:00",
            "notes": "Auto-generated contact"
        })
    
    return contacts

def main():
    """Main function to enhance the organ trafficking UFDR file"""
    print("Enhancing UFDR_FILE.format with realistic organ trafficking story...\n")
    
    if not CASE_DIR.exists():
        print(f"Error: Case directory {CASE_DIR} does not exist!")
        return
    
    base_date = datetime(2025, 10, 15, 10, 0, 0)
    
    # Update SMS messages (3200 messages)
    sms_file = CASE_DIR / "Artifacts" / "SMS" / "sms.json"
    if sms_file.exists():
        messages = generate_realistic_messages(base_date, 3200)
        with open(sms_file, 'w', encoding='utf-8') as f:
            json.dump(messages, f, indent=2, ensure_ascii=False)
        print(f"[OK] Updated SMS messages ({len(messages)} messages)")
    
    # Update WhatsApp messages (3200 messages)
    whatsapp_file = CASE_DIR / "Artifacts" / "WhatsApp" / "whatsapp.json"
    if whatsapp_file.exists():
        messages = generate_realistic_messages(base_date, 3200)
        with open(whatsapp_file, 'w', encoding='utf-8') as f:
            json.dump(messages, f, indent=2, ensure_ascii=False)
        print(f"[OK] Updated WhatsApp messages ({len(messages)} messages)")
    
    # Update Calls (1100 calls)
    calls_file = CASE_DIR / "Artifacts" / "Calls" / "calls.json"
    if calls_file.exists():
        calls = generate_realistic_calls(base_date, 1100)
        with open(calls_file, 'w', encoding='utf-8') as f:
            json.dump(calls, f, indent=2, ensure_ascii=False)
        print(f"[OK] Updated call logs ({len(calls)} calls)")
    
    # Update Contacts
    contacts_file = CASE_DIR / "Artifacts" / "Contacts" / "contacts.json"
    if contacts_file.exists():
        contacts = update_contacts()
        with open(contacts_file, 'w', encoding='utf-8') as f:
            json.dump(contacts, f, indent=2, ensure_ascii=False)
        print(f"[OK] Updated contacts ({len(contacts)} contacts)")
    
    # Update case_info.json
    case_info_file = CASE_DIR / "__metadata__" / "case_info.json"
    if case_info_file.exists():
        with open(case_info_file, 'r', encoding='utf-8') as f:
            case_info = json.load(f)
        
        case_info["description"] = "Investigation into illegal organ trafficking operation led by Dr. Arjun Mehta, a practicing surgeon. Evidence shows coordination with broker Sahil Kapoor, anesthesiologist Dr. Priya Sharma, OR nurse Ravi Kumar, and other medical professionals to illegally harvest and sell organs. Communications reveal planning of procedures, payment arrangements, and attempts to cover up illegal activities. Multiple procedures conducted at private clinic with falsified documentation."
        case_info["victim_name"] = "Multiple Unknown Donors"
        case_info["location"] = "Private Clinic, Sector 8, Delhi"
        case_info["suspects"] = [
            {
                "name": "Dr. Arjun Mehta",
                "role": "Primary Suspect - Surgeon/Coordinator",
                "status": "Under Investigation",
                "phone": "+919988776655",
                "device_owner": True
            },
            {
                "name": "Sahil Kapoor",
                "role": "Organ Broker",
                "status": "Under Investigation",
                "phone": "+919911223344"
            },
            {
                "name": "Dr. Priya Sharma",
                "role": "Anesthesiologist - Accomplice",
                "status": "Under Investigation",
                "phone": "+919876543210"
            },
            {
                "name": "Ravi Kumar",
                "role": "OR Nurse - Accomplice",
                "status": "Under Investigation",
                "phone": "+919123456789"
            },
            {
                "name": "Vikram Singh",
                "role": "Buyer's Agent",
                "status": "Under Investigation",
                "phone": "+919555443322"
            },
            {
                "name": "Amit Verma",
                "role": "Clinic Manager - Accomplice",
                "status": "Under Investigation",
                "phone": "+919444332211"
            },
            {
                "name": "Neha Patel",
                "role": "Lab Technician - Accomplice",
                "status": "Under Investigation",
                "phone": "+919333221100"
            }
        ]
        case_info["evidence_tags"] = [
            "organ_trafficking",
            "medical_conspiracy",
            "illegal_procedures",
            "falsified_documentation",
            "payment_arrangements",
            "cover_up_attempts",
            "multiple_suspects",
            "deleted_messages",
            "encrypted_communications"
        ]
        
        with open(case_info_file, 'w', encoding='utf-8') as f:
            json.dump(case_info, f, indent=2, ensure_ascii=False)
        print(f"[OK] Updated case_info.json")
    
    print("\n[OK] Enhancement complete!")

if __name__ == "__main__":
    main()


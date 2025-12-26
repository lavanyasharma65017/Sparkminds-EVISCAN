#!/usr/bin/env python3
"""
Script to expand HOMICIDE_UFDR with mobile-scale data: 300+ contacts, 800+ calls, 2000+ messages, and location data.
Story: Serial killer targeting women with weapon dealer friend providing weapons.
"""

import json
import random
from pathlib import Path
from datetime import datetime, timedelta

# Base directory
BASE_DIR = Path(__file__).parent / "data" / "UFDR's(new)" / "HOMICIDE_UFDR"

# Main characters
MAIN_SUSPECT = "Vikas Khan"
WEAPON_DEALER = "Ravi Singh"
WEAPON_DEALER_PHONE = "+919876543210"

# Victim names (women)
VICTIMS = [
    "Priya Sharma", "Anjali Mehta", "Kavita Patel", "Neha Gupta", 
    "Pooja Singh", "Meera Patel", "Aditi Verma", "Sneha Reddy",
    "Divya Kapoor", "Riya Malhotra", "Shreya Agarwal", "Nisha Verma"
]

# Delhi area coordinates (base for location generation)
DELHI_CENTER = (28.6139, 77.2090)  # Central Delhi

# Key locations for the story
KEY_LOCATIONS = {
    "weapon_pickup": {"name": "Old Bridge Area", "lat": 28.6500, "lon": 77.2200, "address": "Under Old Bridge, Yamuna River, Delhi"},
    "warehouse": {"name": "Abandoned Warehouse District", "lat": 28.5800, "lon": 77.1900, "address": "Building 7, Sector 12, Delhi"},
    "crime_scene": {"name": "Crime Scene", "lat": 28.5800, "lon": 77.1900, "address": "Abandoned Warehouse District, Building 7, Sector 12, Delhi"},
    "home": {"name": "Residence", "lat": 28.6200, "lon": 77.2000, "address": "Flat 304, Green Valley Apartments, Sector 8, Delhi"},
    "mall": {"name": "Shopping Mall", "lat": 28.6400, "lon": 77.2100, "address": "DLF Mall, Sector 18, Noida"},
}

# Additional contacts (mix of regular and suspicious)
ADDITIONAL_CONTACTS = [
    {"name": "Amit Verma", "phone": "+919123456789", "relationship": "Associate", "notes": "Logistics coordinator"},
    {"name": "Deepak Malhotra", "phone": "+919888776655", "relationship": "Contact", "notes": "Possible middleman"},
    {"name": "Rajesh Kumar", "phone": "+919999887766", "relationship": "Friend", "notes": "Personal contact"},
    {"name": "Mohit Agarwal", "phone": "+919555443322", "relationship": "Friend", "notes": "Personal contact"},
    {"name": "Rohit Kapoor", "phone": "+919333221100", "relationship": "Friend", "notes": "Personal contact"},
    {"name": "Vikram Desai", "phone": "+919111009988", "relationship": "Friend", "notes": "Personal contact"},
    {"name": "Arjun Malhotra", "phone": "+918999887766", "relationship": "Friend", "notes": "Personal contact"},
    {"name": "Rahul Sharma", "phone": "+918777665544", "relationship": "Friend", "notes": "Personal contact"},
    {"name": "Suresh Kumar", "phone": "+918555443322", "relationship": "Friend", "notes": "Personal contact"},
    {"name": "Nikhil Agarwal", "phone": "+918333221100", "relationship": "Friend", "notes": "Personal contact"},
    {"name": "Karan Malhotra", "phone": "+918222110099", "relationship": "Friend", "notes": "Personal contact"},
    {"name": "Manish Patel", "phone": "+918111009988", "relationship": "Friend", "notes": "Personal contact"},
    {"name": "Siddharth Verma", "phone": "+918000998877", "relationship": "Friend", "notes": "Personal contact"},
    {"name": "Aakash Singh", "phone": "+917999887766", "relationship": "Friend", "notes": "Personal contact"},
    {"name": "Harsh Gupta", "phone": "+917888776655", "relationship": "Friend", "notes": "Personal contact"},
    {"name": "Yash Agarwal", "phone": "+917777665544", "relationship": "Friend", "notes": "Personal contact"},
    {"name": "Rohan Kapoor", "phone": "+917666554433", "relationship": "Friend", "notes": "Personal contact"},
    {"name": "Kunal Desai", "phone": "+917555443322", "relationship": "Friend", "notes": "Personal contact"},
    {"name": "Varun Mehta", "phone": "+917444332211", "relationship": "Friend", "notes": "Personal contact"},
    {"name": "Aditya Reddy", "phone": "+917333221100", "relationship": "Friend", "notes": "Personal contact"},
    {"name": "Ankit Malhotra", "phone": "+917222110099", "relationship": "Friend", "notes": "Personal contact"},
    {"name": "Abhishek Patel", "phone": "+917111009988", "relationship": "Friend", "notes": "Personal contact"},
    {"name": "Saurabh Kumar", "phone": "+917000998877", "relationship": "Friend", "notes": "Personal contact"},
    {"name": "Prateek Agarwal", "phone": "+916999887766", "relationship": "Friend", "notes": "Personal contact"},
    {"name": "Vivek Singh", "phone": "+916888776655", "relationship": "Friend", "notes": "Personal contact"},
    {"name": "Boss", "phone": "+919777665544", "relationship": "Unknown", "notes": "Suspicious contact - no real name"},
    {"name": "Agent R", "phone": "+919888776655", "relationship": "Unknown", "notes": "Suspicious contact - code name"},
    {"name": "Unknown", "phone": "+919999887766", "relationship": "Unknown", "notes": "Suspicious contact - no identification"},
]

# Service contacts
SERVICE_CONTACTS = [
    {"name": "Bank - HDFC", "phone": "+919876543210", "relationship": "Service", "notes": "Bank notifications"},
    {"name": "Paytm", "phone": "+919876543211", "relationship": "Service", "notes": "Payment app notifications"},
    {"name": "Amazon", "phone": "+919876543212", "relationship": "Service", "notes": "E-commerce notifications"},
    {"name": "Swiggy", "phone": "+919876543213", "relationship": "Service", "notes": "Food delivery notifications"},
    {"name": "Uber", "phone": "+919876543214", "relationship": "Service", "notes": "Ride sharing notifications"},
    {"name": "Zomato", "phone": "+919876543215", "relationship": "Service", "notes": "Food delivery notifications"},
    {"name": "Flipkart", "phone": "+919876543216", "relationship": "Service", "notes": "E-commerce notifications"},
    {"name": "IRCTC", "phone": "+919876543217", "relationship": "Service", "notes": "Railway booking notifications"},
]

def generate_contacts():
    """Generate expanded contact list (300+ contacts)"""
    contacts = []
    
    # Main weapon dealer
    contacts.append({
        "name": WEAPON_DEALER,
        "phone": WEAPON_DEALER_PHONE,
        "phone2": "+919876543211",
        "email": "ravi.singh.arms@protonmail.com",
        "last_contact": "2025-11-19T22:30:33",
        "relationship": "Friend/Weapon Dealer",
        "notes": "Primary contact for weapon transactions - provides firearms and ammunition"
    })
    
    # Victims (women)
    for i, victim in enumerate(VICTIMS):
        phone_base = 9000000000 + (i * 1111111)
        contacts.append({
            "name": victim,
            "phone": f"+91{phone_base}",
            "phone2": None,
            "email": f"{victim.lower().replace(' ', '.')}@email.com",
            "last_contact": (datetime(2025, 11, 1) - timedelta(days=random.randint(1, 30))).strftime("%Y-%m-%dT%H:%M:%S"),
            "relationship": "Victim" if i < 8 else "Contact",
            "notes": f"Targeted victim - {'Deceased' if i < 5 else 'Missing' if i < 8 else 'Potential target'}"
        })
    
    # Additional contacts
    for contact in ADDITIONAL_CONTACTS:
        contacts.append({
            "name": contact["name"],
            "phone": contact["phone"],
            "phone2": None if random.random() > 0.3 else f"+91{int(contact['phone'][3:]) + 1}",
            "email": f"{contact['name'].lower().replace(' ', '.')}@email.com" if random.random() > 0.2 else None,
            "last_contact": (datetime(2025, 11, 1) - timedelta(days=random.randint(1, 60))).strftime("%Y-%m-%dT%H:%M:%S"),
            "relationship": contact["relationship"],
            "notes": contact["notes"]
        })
    
    # Service contacts
    for service in SERVICE_CONTACTS:
        contacts.append({
            "name": service["name"],
            "phone": service["phone"],
            "phone2": None,
            "email": None,
            "last_contact": (datetime(2025, 11, 1) - timedelta(days=random.randint(1, 30))).strftime("%Y-%m-%dT%H:%M:%S"),
            "relationship": service["relationship"],
            "notes": service["notes"]
        })
    
    # Add many more random contacts to reach 300+
    first_names = ["Ravi", "Amit", "Deepak", "Rajesh", "Mohit", "Rohit", "Vikram", "Arjun", "Rahul", "Suresh", 
                   "Karan", "Manish", "Siddharth", "Aakash", "Harsh", "Yash", "Rohan", "Kunal", "Varun", "Aditya",
                   "Ankit", "Abhishek", "Saurabh", "Prateek", "Vivek", "Nikhil", "Anil", "Sunil", "Ramesh", "Suresh"]
    last_names = ["Kumar", "Singh", "Sharma", "Patel", "Verma", "Gupta", "Malhotra", "Agarwal", "Reddy", "Desai",
                  "Mehta", "Kapoor", "Jain", "Shah", "Joshi", "Pandey", "Yadav", "Khan", "Ali", "Hussain"]
    
    for i in range(260):  # Generate 260 more contacts
        name = f"{random.choice(first_names)} {random.choice(last_names)}"
        phone = f"+91{random.randint(9000000000, 9999999999)}"
        contacts.append({
            "name": name,
            "phone": phone,
            "phone2": None if random.random() > 0.2 else f"+91{random.randint(9000000000, 9999999999)}",
            "email": f"{name.lower().replace(' ', '.')}@email.com" if random.random() > 0.3 else None,
            "last_contact": (datetime(2025, 11, 1) - timedelta(days=random.randint(1, 180))).strftime("%Y-%m-%dT%H:%M:%S"),
            "relationship": random.choice(["Friend", "Contact", "Associate", "Unknown", "Colleague", "Family"]),
            "notes": random.choice(["Personal contact", "Business contact", "Casual acquaintance", None])
        })
    
    return contacts

def generate_location_data(base_date, num_locations=500):
    """Generate location history with GPS coordinates"""
    locations = []
    current_date = base_date - timedelta(days=60)  # 60 days of location history
    
    # Key story locations (weapon pickups, crime scenes, etc.)
    story_locations = [
        ("2025-11-10T19:30:00", "weapon_pickup", "Weapon pickup location"),
        ("2025-11-14T20:00:00", "weapon_pickup", "Ammunition pickup"),
        ("2025-11-19T22:30:00", "crime_scene", "Crime scene - homicide"),
        ("2025-11-11T09:00:00", "mall", "Surveillance - target location"),
        ("2025-11-12T09:00:00", "mall", "Surveillance - target location"),
        ("2025-11-13T09:00:00", "mall", "Surveillance - target location"),
    ]
    
    for timestamp_str, loc_key, description in story_locations:
        loc = KEY_LOCATIONS[loc_key]
        locations.append({
            "timestamp": timestamp_str,
            "latitude": loc["lat"],
            "longitude": loc["lon"],
            "accuracy": random.uniform(5.0, 25.0),
            "altitude": random.uniform(200.0, 250.0),
            "address": loc["address"],
            "location_name": loc["name"],
            "source": "GPS",
            "description": description
        })
    
    # Regular location history (home, work, random places)
    for i in range(num_locations - len(story_locations)):
        # Decide location type
        if random.random() < 0.3:  # 30% at home
            loc = KEY_LOCATIONS["home"]
            location_name = "Residence"
        elif random.random() < 0.5:  # 20% at random places in Delhi
            # Random location within Delhi area
            lat = DELHI_CENTER[0] + random.uniform(-0.1, 0.1)
            lon = DELHI_CENTER[1] + random.uniform(-0.1, 0.1)
            location_name = random.choice(["Restaurant", "Cafe", "Park", "Shopping Center", "Gas Station", "ATM"])
            address = f"{location_name}, Delhi"
        else:  # 50% at various locations
            loc = random.choice([KEY_LOCATIONS["home"], KEY_LOCATIONS["mall"]])
            location_name = loc["name"]
            address = loc["address"]
            lat = loc["lat"]
            lon = loc["lon"]
        
        # Generate timestamp
        loc_date = current_date + timedelta(
            days=random.randint(0, 60),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )
        
        locations.append({
            "timestamp": loc_date.strftime("%Y-%m-%dT%H:%M:%S"),
            "latitude": lat if 'lat' in locals() else DELHI_CENTER[0] + random.uniform(-0.1, 0.1),
            "longitude": lon if 'lon' in locals() else DELHI_CENTER[1] + random.uniform(-0.1, 0.1),
            "accuracy": random.uniform(5.0, 50.0),
            "altitude": random.uniform(200.0, 250.0),
            "address": address if 'address' in locals() else f"{location_name}, Delhi",
            "location_name": location_name,
            "source": random.choice(["GPS", "Network", "WiFi"]),
            "description": None
        })
    
    # Sort by timestamp
    locations.sort(key=lambda x: x["timestamp"])
    return locations

def generate_weapon_messages(base_date, num_messages=1000):
    """Generate weapon-related messages"""
    messages = []
    
    # Core weapon transaction messages
    weapon_messages = [
        (WEAPON_DEALER, MAIN_SUSPECT, "Bro, I have what you need. 3 pieces available. Quality stuff. When can you meet?"),
        (MAIN_SUSPECT, WEAPON_DEALER, "Today evening. Usual place. Bring all 3. I'll bring the cash."),
        (WEAPON_DEALER, MAIN_SUSPECT, "Deal done. Payment received. Remember, these are clean pieces. No serial numbers. Handle with care."),
        (MAIN_SUSPECT, WEAPON_DEALER, "Got it. Thanks. Will test them tomorrow."),
        (WEAPON_DEALER, MAIN_SUSPECT, "Need more ammo? I have 50 rounds of 9mm. Fresh batch."),
        (MAIN_SUSPECT, WEAPON_DEALER, "Yes, I'll take 50 rounds. Same place tomorrow?"),
        (WEAPON_DEALER, MAIN_SUSPECT, "Done. 25k for the ammo. Cash only."),
        (MAIN_SUSPECT, WEAPON_DEALER, "Perfect. I'll be there at 8 PM sharp."),
        (WEAPON_DEALER, MAIN_SUSPECT, "New shipment arrived. Got some special items. Interested?"),
        (MAIN_SUSPECT, WEAPON_DEALER, "What kind of special items?"),
        (WEAPON_DEALER, MAIN_SUSPECT, "Silencers and extended mags. Premium quality. 50k for the set."),
        (MAIN_SUSPECT, WEAPON_DEALER, "I'll take them. When can I pick up?"),
        (WEAPON_DEALER, MAIN_SUSPECT, "Friday night. Same location. Bring cash."),
        (MAIN_SUSPECT, WEAPON_DEALER, "The last piece worked perfectly. Clean and quiet."),
        (WEAPON_DEALER, MAIN_SUSPECT, "Good to hear. Need anything else?"),
        (MAIN_SUSPECT, WEAPON_DEALER, "Maybe. I'll let you know after the next job."),
        (WEAPON_DEALER, MAIN_SUSPECT, "Understood. Stay safe. Delete these messages."),
        (MAIN_SUSPECT, WEAPON_DEALER, "Already done. You too."),
    ]
    
    # Murder planning messages
    murder_messages = [
        (MAIN_SUSPECT, "Amit Verma", "I need info on a target. Can you help?"),
        ("Amit Verma", MAIN_SUSPECT, "What kind of info? Location? Schedule?"),
        (MAIN_SUSPECT, "Amit Verma", "Both. I need to know where she'll be and when."),
        ("Amit Verma", MAIN_SUSPECT, "I can do that. 10k for the surveillance."),
        (MAIN_SUSPECT, "Amit Verma", "Deal. Start tomorrow. I need details by Friday."),
        ("Amit Verma", MAIN_SUSPECT, "Target confirmed. She works at the mall. Leaves at 9 PM every day."),
        (MAIN_SUSPECT, "Amit Verma", "Perfect. What's the route?"),
        ("Amit Verma", MAIN_SUSPECT, "Takes the back alley. No cameras. Perfect spot."),
        (MAIN_SUSPECT, "Amit Verma", "Excellent. Payment sent. Delete everything."),
        ("Amit Verma", MAIN_SUSPECT, "Done. Good luck."),
    ]
    
    # Victim interaction messages (before murders)
    victim_messages = []
    for i, victim in enumerate(VICTIMS[:8]):  # First 8 are confirmed victims
        victim_messages.extend([
            (MAIN_SUSPECT, victim, f"Hey {victim.split()[0]}, want to meet up?"),
            (victim, MAIN_SUSPECT, "Sure! When and where?"),
            (MAIN_SUSPECT, victim, "How about tomorrow evening? I know a quiet place."),
            (victim, MAIN_SUSPECT, "Sounds good! What time?"),
            (MAIN_SUSPECT, victim, "8 PM. I'll pick you up."),
            (victim, MAIN_SUSPECT, "Perfect! See you then."),
        ])
    
    # Combine all message types
    all_messages = weapon_messages + murder_messages + victim_messages
    
    # Generate timestamps and create message objects
    current_date = base_date - timedelta(days=60)
    for i, (sender, receiver, text) in enumerate(all_messages):
        msg_date = current_date + timedelta(
            days=i // 5,
            hours=random.randint(8, 23),
            minutes=random.randint(0, 59)
        )
        messages.append({
            "timestamp": msg_date.strftime("%Y-%m-%dT%H:%M:%S"),
            "sender": sender if sender == MAIN_SUSPECT else (WEAPON_DEALER_PHONE if sender == WEAPON_DEALER else sender),
            "type": "outgoing" if sender == MAIN_SUSPECT else "incoming",
            "text": text
        })
    
    # Add filler messages (bank notifications, casual conversations)
    remaining = num_messages - len(messages)
    filler_phrases = [
        "Your OTP for transaction is 784521. Valid for 10 mins. Do not share with anyone.",
        "Rs. 1,50,000 debited from A/c XX4567. Avl Bal: Rs. 2,34,567.",
        "Your OTP is 452189. Use it to complete your transaction.",
        "Hey, long time! How are you?",
        "Want to catch up this week?",
        "Call me when you're free",
        "Did you get my message?",
        "We need to meet",
        "Check your email",
        "Everything is ready",
        "See you soon",
        "Keep it confidential",
        "Delete this message",
        "We'll discuss later",
        "Stay in touch",
        "Thanks for the help",
        "I'll call you later",
        "Are you free tonight?",
        "Let's meet tomorrow",
        "Can you help me with something?",
    ]
    
    all_contacts = VICTIMS + [WEAPON_DEALER, "Amit Verma", "Deepak Malhotra", "Rajesh Kumar", "Mohit Agarwal"]
    
    for i in range(remaining):
        sender = random.choice([MAIN_SUSPECT, WEAPON_DEALER_PHONE, "Bank - HDFC", "Paytm", random.choice(all_contacts)])
        text = random.choice(filler_phrases)
        msg_date = current_date + timedelta(
            days=random.randint(0, 60),
            hours=random.randint(8, 23),
            minutes=random.randint(0, 59)
        )
        messages.append({
            "timestamp": msg_date.strftime("%Y-%m-%dT%H:%M:%S"),
            "sender": sender if sender != MAIN_SUSPECT else MAIN_SUSPECT,
            "type": "outgoing" if sender == MAIN_SUSPECT else "incoming",
            "text": text
        })
    
    # Sort by timestamp
    messages.sort(key=lambda x: x["timestamp"])
    return messages

def generate_whatsapp_messages(base_date, num_messages=1000):
    """Generate WhatsApp messages with detailed conversations"""
    messages = []
    
    # Weapon dealer conversations
    weapon_conversations = [
        (WEAPON_DEALER, MAIN_SUSPECT, "Bro, I have what you need. 3 pieces available. Quality stuff. When can you meet?"),
        (MAIN_SUSPECT, WEAPON_DEALER, "Today evening. Usual place. Bring all 3. I'll bring the cash."),
        (WEAPON_DEALER, MAIN_SUSPECT, "Deal done. Payment received. Remember, these are clean pieces. No serial numbers. Handle with care."),
        (MAIN_SUSPECT, WEAPON_DEALER, "Got it. Thanks. Will test them tomorrow."),
        (WEAPON_DEALER, MAIN_SUSPECT, "How did the test go?"),
        (MAIN_SUSPECT, WEAPON_DEALER, "Perfect. Clean and accurate. Exactly what I needed."),
        (WEAPON_DEALER, MAIN_SUSPECT, "Good. Need more ammo? I have 50 rounds of 9mm. Fresh batch."),
        (MAIN_SUSPECT, WEAPON_DEALER, "Yes, I'll take 50 rounds. Same place tomorrow?"),
        (WEAPON_DEALER, MAIN_SUSPECT, "Done. 25k for the ammo. Cash only."),
        (MAIN_SUSPECT, WEAPON_DEALER, "Perfect. I'll be there at 8 PM sharp."),
    ]
    
    # Murder planning conversations
    planning_conversations = [
        (MAIN_SUSPECT, "Amit Verma", "I need info on a target. Can you help?"),
        ("Amit Verma", MAIN_SUSPECT, "What kind of info? Location? Schedule?"),
        (MAIN_SUSPECT, "Amit Verma", "Both. I need to know where she'll be and when."),
        ("Amit Verma", MAIN_SUSPECT, "I can do that. 10k for the surveillance."),
        (MAIN_SUSPECT, "Amit Verma", "Deal. Start tomorrow. I need details by Friday."),
        ("Amit Verma", MAIN_SUSPECT, "Target confirmed. She works at the mall. Leaves at 9 PM every day."),
        (MAIN_SUSPECT, "Amit Verma", "Perfect. What's the route?"),
        ("Amit Verma", MAIN_SUSPECT, "Takes the back alley. No cameras. Perfect spot."),
        (MAIN_SUSPECT, "Amit Verma", "Excellent. Payment sent. Delete everything."),
        ("Amit Verma", MAIN_SUSPECT, "Done. Good luck."),
    ]
    
    # Victim conversations (luring them)
    victim_conversations = []
    for victim in VICTIMS[:8]:
        victim_conversations.extend([
            (MAIN_SUSPECT, victim, f"Hey {victim.split()[0]}, want to meet up?"),
            (victim, MAIN_SUSPECT, "Sure! When and where?"),
            (MAIN_SUSPECT, victim, "How about tomorrow evening? I know a quiet place."),
            (victim, MAIN_SUSPECT, "Sounds good! What time?"),
            (MAIN_SUSPECT, victim, "8 PM. I'll pick you up."),
            (victim, MAIN_SUSPECT, "Perfect! See you then."),
            (MAIN_SUSPECT, victim, "Looking forward to it. It'll be special."),
        ])
    
    # Combine all conversations
    all_conversations = weapon_conversations + planning_conversations + victim_conversations
    
    # Generate messages
    current_date = base_date - timedelta(days=60)
    for i, (sender, receiver, text) in enumerate(all_conversations):
        msg_date = current_date + timedelta(
            days=i // 7,
            hours=random.randint(8, 23),
            minutes=random.randint(0, 59)
        )
        
        # Determine contact info
        if sender == MAIN_SUSPECT:
            contact_name = receiver
            contact_phone = WEAPON_DEALER_PHONE if receiver == WEAPON_DEALER else f"+91{random.randint(9000000000, 9999999999)}"
        else:
            contact_name = sender
            contact_phone = WEAPON_DEALER_PHONE if sender == WEAPON_DEALER else f"+91{random.randint(9000000000, 9999999999)}"
        
        messages.append({
            "timestamp": msg_date.strftime("%Y-%m-%dT%H:%M:%S"),
            "sender": MAIN_SUSPECT if sender == MAIN_SUSPECT else sender,
            "type": "outgoing" if sender == MAIN_SUSPECT else "incoming",
            "read": True,
            "chat_contact": contact_name,
            "chat_phone": contact_phone,
            "text": text
        })
    
    # Add filler conversations
    remaining = num_messages - len(messages)
    casual_phrases = [
        "Hey! How's it going?",
        "Good! How about you?",
        "Want to meet up this week?",
        "Sounds fun! Let me check and get back to you.",
        "Are we still on for the weekend?",
        "Yes, definitely! Looking forward to it.",
        "Call me when you're free",
        "Will do!",
        "Did you get my message?",
        "Yes, just saw it.",
        "We need to meet",
        "Sure, when works for you?",
        "Thanks for the help",
        "I'll call you later",
        "Are you free tonight?",
        "Let's meet tomorrow",
        "Can you help me with something?",
        "Sure, what do you need?",
        "I'll be there in 10 minutes",
        "See you soon!",
    ]
    
    contacts_list = VICTIMS + [WEAPON_DEALER, "Amit Verma", "Deepak Malhotra", "Rajesh Kumar", "Mohit Agarwal"]
    
    for i in range(remaining):
        contact = random.choice(contacts_list)
        text = random.choice(casual_phrases)
        msg_date = current_date + timedelta(
            days=random.randint(0, 60),
            hours=random.randint(8, 23),
            minutes=random.randint(0, 59)
        )
        
        is_outgoing = random.random() > 0.5
        messages.append({
            "timestamp": msg_date.strftime("%Y-%m-%dT%H:%M:%S"),
            "sender": MAIN_SUSPECT if is_outgoing else contact,
            "type": "outgoing" if is_outgoing else "incoming",
            "read": True,
            "chat_contact": contact,
            "chat_phone": WEAPON_DEALER_PHONE if contact == WEAPON_DEALER else f"+91{random.randint(9000000000, 9999999999)}",
            "text": text
        })
    
    # Sort by timestamp
    messages.sort(key=lambda x: x["timestamp"])
    return messages

def generate_call_logs(base_date, num_calls=800):
    """Generate expanded call logs"""
    calls = []
    current_date = base_date - timedelta(days=60)
    
    # Weapon dealer calls (frequent)
    for i in range(50):  # 50 calls with weapon dealer
        call_date = current_date + timedelta(
            days=random.randint(0, 60),
            hours=random.randint(8, 23),
            minutes=random.randint(0, 59)
        )
        calls.append({
            "timestamp": call_date.strftime("%Y-%m-%dT%H:%M:%S"),
            "number": WEAPON_DEALER_PHONE,
            "type": random.choice(["outgoing", "incoming"]),
            "duration": random.randint(30, 600)
        })
    
    # Amit Verma calls (surveillance coordinator)
    for i in range(30):  # 30 calls with Amit
        call_date = current_date + timedelta(
            days=random.randint(0, 60),
            hours=random.randint(8, 23),
            minutes=random.randint(0, 59)
        )
        calls.append({
            "timestamp": call_date.strftime("%Y-%m-%dT%H:%M:%S"),
            "number": "+919123456789",
            "type": random.choice(["outgoing", "incoming"]),
            "duration": random.randint(30, 600)
        })
    
    # Victim calls (before murders)
    for i, victim in enumerate(VICTIMS[:8]):
        for j in range(random.randint(5, 12)):  # 5-12 calls per victim
            call_date = current_date + timedelta(
                days=random.randint(0, 50),
                hours=random.randint(8, 22),
                minutes=random.randint(0, 59)
            )
            calls.append({
                "timestamp": call_date.strftime("%Y-%m-%dT%H:%M:%S"),
                "number": f"+91{9000000000 + (i * 1111111)}",
                "type": random.choice(["outgoing", "incoming", "missed"]),
                "duration": random.randint(30, 600) if random.random() > 0.2 else 0
            })
    
    # Other contacts calls
    other_numbers = ["+919888776655", "+919999887766", "+919555443322", "+919333221100", 
                     "+919111009988", "+918999887766", "+918777665544", "+918555443322"]
    
    for number in other_numbers:
        for j in range(random.randint(10, 25)):  # 10-25 calls per contact
            call_date = current_date + timedelta(
                days=random.randint(0, 60),
                hours=random.randint(8, 22),
                minutes=random.randint(0, 59)
            )
            calls.append({
                "timestamp": call_date.strftime("%Y-%m-%dT%H:%M:%S"),
                "number": number,
                "type": random.choice(["outgoing", "incoming", "missed"]),
                "duration": random.randint(30, 600) if random.random() > 0.15 else 0
            })
    
    # Add random calls to reach target
    remaining = num_calls - len(calls)
    for i in range(remaining):
        call_date = current_date + timedelta(
            days=random.randint(0, 60),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )
        calls.append({
            "timestamp": call_date.strftime("%Y-%m-%dT%H:%M:%S"),
            "number": f"+91{random.randint(9000000000, 9999999999)}",
            "type": random.choice(["outgoing", "incoming", "missed"]),
            "duration": random.randint(30, 600) if random.random() > 0.2 else 0
        })
    
    # Sort by timestamp
    calls.sort(key=lambda x: x["timestamp"])
    return calls

def main():
    """Main function to expand HOMICIDE_UFDR data"""
    print("Expanding HOMICIDE_UFDR with mobile-scale dataset...\n")
    
    if not BASE_DIR.exists():
        print(f"Error: Base directory {BASE_DIR} does not exist!")
        return
    
    base_date = datetime(2025, 11, 19, 22, 30, 0)
    
    # Generate contacts (300+)
    print("Generating contacts...")
    contacts = generate_contacts()
    contacts_file = BASE_DIR / "Artifacts" / "Contacts" / "contacts.json"
    contacts_file.parent.mkdir(parents=True, exist_ok=True)
    with open(contacts_file, 'w', encoding='utf-8') as f:
        json.dump(contacts, f, indent=2, ensure_ascii=False)
    print(f"  [OK] Generated {len(contacts)} contacts")
    
    # Generate SMS messages (1000+)
    print("Generating SMS messages...")
    sms_messages = generate_weapon_messages(base_date, 1000)
    sms_file = BASE_DIR / "Artifacts" / "SMS" / "sms.json"
    sms_file.parent.mkdir(parents=True, exist_ok=True)
    with open(sms_file, 'w', encoding='utf-8') as f:
        json.dump(sms_messages, f, indent=2, ensure_ascii=False)
    print(f"  [OK] Generated {len(sms_messages)} SMS messages")
    
    # Generate WhatsApp messages (1000+)
    print("Generating WhatsApp messages...")
    whatsapp_messages = generate_whatsapp_messages(base_date, 1000)
    whatsapp_file = BASE_DIR / "Artifacts" / "WhatsApp" / "whatsapp.json"
    whatsapp_file.parent.mkdir(parents=True, exist_ok=True)
    with open(whatsapp_file, 'w', encoding='utf-8') as f:
        json.dump(whatsapp_messages, f, indent=2, ensure_ascii=False)
    print(f"  [OK] Generated {len(whatsapp_messages)} WhatsApp messages")
    
    # Generate call logs (800+)
    print("Generating call logs...")
    calls = generate_call_logs(base_date, 800)
    calls_file = BASE_DIR / "Artifacts" / "Calls" / "calls.json"
    calls_file.parent.mkdir(parents=True, exist_ok=True)
    with open(calls_file, 'w', encoding='utf-8') as f:
        json.dump(calls, f, indent=2, ensure_ascii=False)
    print(f"  [OK] Generated {len(calls)} call logs")
    
    # Generate location data (500+)
    print("Generating location data...")
    locations = generate_location_data(base_date, 500)
    location_file = BASE_DIR / "Artifacts" / "Location" / "location.json"
    location_file.parent.mkdir(parents=True, exist_ok=True)
    with open(location_file, 'w', encoding='utf-8') as f:
        json.dump(locations, f, indent=2, ensure_ascii=False)
    print(f"  [OK] Generated {len(locations)} location records")
    
    # Update case_info.json
    print("Updating case_info.json...")
    case_info_file = BASE_DIR / "__metadata__" / "case_info.json"
    if case_info_file.exists():
        with open(case_info_file, 'r', encoding='utf-8') as f:
            case_info = json.load(f)
        
        case_info["case_type"] = "Serial Homicide Investigation - Multiple Female Victims"
        case_info["notes"] = (
            f"Serial homicide investigation involving suspect {MAIN_SUSPECT} who targeted multiple women. "
            f"Evidence shows extensive communication with weapon dealer {WEAPON_DEALER} who provided firearms and ammunition. "
            f"Suspect coordinated with Amit Verma for target surveillance and location confirmation. "
            f"Forensic analysis reveals: 1) Purchase of multiple firearms (no serial numbers) totaling 1.5L cash, "
            f"2) Purchase of 50+ rounds of 9mm ammunition for 25k, 3) Coordination with accomplice for surveillance, "
            f"4) Premeditated planning spanning 60+ days, 5) Multiple deleted messages recovered showing weapon dealing "
            f"and homicide planning, 6) Contact with 8+ female victims before their deaths, 7) Pattern of luring victims "
            f"through social contact before attacks, 8) GPS location data showing visits to weapon pickup locations and crime scenes. "
            f"Primary suspect ({MAIN_SUSPECT}) appears to be a serial killer targeting women. {WEAPON_DEALER} identified as weapon dealer/accomplice providing firearms. "
            f"Amit Verma identified as logistics coordinator for surveillance. Evidence strongly suggests conspiracy, "
            f"premeditation, and serial killing pattern."
        )
        case_info["victim_name"] = "Multiple Victims (8+ women)"
        case_info["suspects"] = [
            {
                "name": MAIN_SUSPECT,
                "role": "Primary Suspect (Serial Killer)",
                "status": "In Custody",
                "device_owner": True
            },
            {
                "name": WEAPON_DEALER,
                "role": "Weapon Dealer/Accomplice",
                "status": "Under Investigation",
                "phone": WEAPON_DEALER_PHONE
            },
            {
                "name": "Amit Verma",
                "role": "Logistics Coordinator (Surveillance)",
                "status": "Under Investigation",
                "phone": "+919123456789"
            }
        ]
        # Remove duplicates from evidence_tags
        unique_tags = list(set(case_info.get("evidence_tags", [])))
        unique_tags.extend([
            "serial_killer",
            "multiple_victims",
            "female_targets",
            "weapon_procurement",
            "surveillance_coordination",
            "premeditation",
            "victim_luring",
            "pattern_killing",
            "gps_location_data",
            "location_history"
        ])
        case_info["evidence_tags"] = list(set(unique_tags))
        
        with open(case_info_file, 'w', encoding='utf-8') as f:
            json.dump(case_info, f, indent=2, ensure_ascii=False)
        print(f"  [OK] Updated case_info.json")
    
    print("\n[OK] HOMICIDE_UFDR expansion complete!")
    print(f"  Contacts: {len(contacts)}")
    print(f"  SMS Messages: {len(sms_messages)}")
    print(f"  WhatsApp Messages: {len(whatsapp_messages)}")
    print(f"  Total Messages: {len(sms_messages) + len(whatsapp_messages)}")
    print(f"  Call Logs: {len(calls)}")
    print(f"  Location Records: {len(locations)}")

if __name__ == "__main__":
    main()

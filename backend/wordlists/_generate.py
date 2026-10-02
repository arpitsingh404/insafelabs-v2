"""Generate a sizeable rockyou-style password wordlist from a strong seed +
realistic mutations (case, leet, common suffixes/prefixes). Deterministic."""
import os

BASE = [
    # top leaked passwords
    "password", "123456", "123456789", "12345678", "12345", "1234567", "1234567890",
    "qwerty", "abc123", "111111", "123123", "1234", "iloveyou", "000000", "admin",
    "welcome", "monkey", "dragon", "letmein", "football", "baseball", "master",
    "qwertyuiop", "mustang", "shadow", "michael", "superman", "batman", "trustno1",
    "hello", "charlie", "donald", "login", "starwars", "flower", "hottie", "loveme",
    "root", "toor", "test", "guest", "changeme", "secret", "administrator", "ninja",
    "azerty", "computer", "michelle", "jessica", "pepper", "daniel", "andrew",
    "joshua", "summer", "winter", "spring", "autumn", "ashley", "nicole", "chelsea",
    "biteme", "matthew", "access", "yankees", "google", "maverick", "cheese", "hunter",
    "ranger", "buster", "thomas", "robert", "soccer", "hockey", "killer", "george",
    "sexy", "andrea", "purple", "amanda", "jordan", "cameron", "freedom", "ginger",
    "willie", "samsung", "orange", "apple", "banana", "chocolate", "diamond", "silver",
    "golden", "rainbow", "sunshine", "princess", "angel", "tigger", "peanut", "cookie",
    "pumpkin", "buttercup", "snoopy", "garfield", "mickey", "minnie", "goofy", "pluto",
    # names
    "john", "mike", "david", "james", "peter", "steve", "kevin", "brian", "mark",
    "paul", "chris", "tony", "sam", "alex", "jack", "ryan", "sean", "eric", "adam",
    "sara", "anna", "emma", "olivia", "sophia", "mia", "ava", "isabella", "lily",
    "rahul", "amit", "raj", "kumar", "singh", "sharma", "priya", "neha", "pooja",
    "ahmed", "ali", "hassan", "omar", "khan", "fatima", "aisha", "maria", "jose",
    "carlos", "juan", "pedro", "luis", "diego", "sofia", "lucia", "elena",
    # words / teams / places
    "internet", "service", "server", "system", "network", "security", "manager",
    "office", "company", "business", "money", "market", "sales", "support", "welcome1",
    "liverpool", "arsenal", "chelsea", "united", "barcelona", "madrid", "juventus",
    "lakers", "cowboys", "steelers", "raiders", "rangers", "celtic",
    "london", "paris", "newyork", "tokyo", "berlin", "moscow", "dubai", "india",
    "canada", "america", "china", "france", "italy", "spain", "brazil", "mexico",
    # keyboard walks / patterns
    "qazwsx", "zxcvbnm", "asdfgh", "asdfghjkl", "1qaz2wsx", "1q2w3e4r", "1q2w3e",
    "qwe123", "123qwe", "qweasd", "poiuyt", "lkjhgf", "mnbvcx", "qwerty123",
    "passw0rd", "p@ssw0rd", "pa55word", "letmein1", "welcome123", "admin123",
    "root123", "test123", "abcd1234", "a1b2c3", "aa123456", "112233", "121212",
    "654321", "666666", "888888", "999999", "252525", "159753", "789456",
    # tech / gaming / misc
    "minecraft", "fortnite", "pokemon", "zelda", "mario", "sonic", "gaming",
    "gamer", "player", "master1", "warrior", "wizard", "hunter1", "phoenix",
    "matrix", "neo", "hacker", "linux", "windows", "ubuntu", "python", "javascript",
    "coffee", "beer", "whiskey", "vodka", "guitar", "music", "guitar1", "metal",
    "love", "loveyou", "iloveu", "kisses", "forever", "beautiful", "gorgeous",
    "happy", "smile", "family", "friends", "trust", "faith", "hope", "grace",
    "jesus", "christ", "heaven", "angel1", "blessed", "amen", "allah", "krishna",
]

# leet map (single-pass)
LEET = str.maketrans({"a": "@", "o": "0", "e": "3", "i": "1", "s": "$"})
SUFFIXES = ["", "1", "12", "123", "1234", "12345", "!", "@", "#", "123!", "1!",
            "01", "007", "69", "99", "00", "111", "321", "2020", "2021", "2022",
            "2023", "2024", "2025", "2026", "2019", "2018", "@123", "!23"]
PREFIXES = ["", "!", "1", "@"]


def variants(word):
    forms = {word, word.capitalize(), word.upper(), word.title()}
    if any(c in word for c in "aeios"):
        forms.add(word.translate(LEET))
        forms.add(word.capitalize().translate(LEET))
    return forms


def main():
    out = set()
    for base in BASE:
        for form in variants(base):
            for pre in PREFIXES:
                for suf in SUFFIXES:
                    cand = pre + form + suf
                    if 3 <= len(cand) <= 24:
                        out.add(cand)
    # also raw bases with no mutation guaranteed first
    ordered = list(BASE) + sorted(out)
    seen, final = set(), []
    for w in ordered:
        if w not in seen:
            seen.add(w)
            final.append(w)
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "rockyou_lite.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(final))
    print(f"wrote {len(final)} passwords to {path}")


if __name__ == "__main__":
    main()

import random
import string
import secrets
from collections import Counter

class UltraAdvancedPasswordGenerator:
    def __init__(self):
        # Extended collection of uncommon letters with frequency weighting
        self.ultra_rare_letters = ['Q', 'q', 'X', 'x', 'Z', 'z', 'J', 'j']  # Rarest
        self.rare_letters = ['K', 'k', 'V', 'v', 'W', 'w', 'Y', 'y']        # Very rare
        self.uncommon_letters = ['F', 'f', 'G', 'g', 'H', 'h', 'B', 'b', 'P', 'p', 'M', 'm']
        self.medium_letters = ['C', 'c', 'D', 'd', 'U', 'u', 'L', 'l']
        
        # Extended special symbols with categories
        self.basic_symbols = "!@#$%^&*()"
        self.advanced_symbols = "_+-=[]{}|\\:;\"'<>,.?/"
        self.unicode_symbols = "§±∞÷≠≤≥∫∑∏√∆Ω"
        self.all_symbols = self.basic_symbols + self.advanced_symbols + self.unicode_symbols
        
        # Complex number patterns
        self.hex_digits = "0123456789ABCDEF"
        self.binary_digits = "01"
        
        # Complexity patterns
        self.complexity_patterns = [
            'alternating_case',
            'pyramid_case',
            'wave_case',
            'random_burst',
            'fibonacci_case'
        ]
    
    def apply_ultra_case_complexity(self, text, pattern='random'):
        """Apply extremely complex case patterns"""
        if not text:
            return text
            
        result = list(text.lower())
        
        if pattern == 'alternating_case':
            for i in range(len(result)):
                if result[i].isalpha():
                    result[i] = result[i].upper() if i % 2 == 0 else result[i].lower()
                    
        elif pattern == 'pyramid_case':
            mid = len(result) // 2
            for i in range(len(result)):
                if result[i].isalpha():
                    distance_from_mid = abs(i - mid)
                    result[i] = result[i].upper() if distance_from_mid % 2 == 0 else result[i].lower()
                    
        elif pattern == 'wave_case':
            import math
            for i in range(len(result)):
                if result[i].isalpha():
                    wave_val = math.sin(i * 0.5)
                    result[i] = result[i].upper() if wave_val > 0 else result[i].lower()
                    
        elif pattern == 'fibonacci_case':
            fib = [0, 1]
            while fib[-1] < len(result):
                fib.append(fib[-1] + fib[-2])
            for i in range(len(result)):
                if result[i].isalpha():
                    result[i] = result[i].upper() if i in fib else result[i].lower()
                    
        else:  # random_burst - most complex
            burst_length = random.randint(2, 4)
            current_case = random.choice([str.upper, str.lower])
            chars_in_burst = 0
            
            for i in range(len(result)):
                if result[i].isalpha():
                    if chars_in_burst >= burst_length:
                        current_case = str.upper if current_case == str.lower else str.lower
                        burst_length = random.randint(2, 4)
                        chars_in_burst = 0
                    result[i] = current_case(result[i])
                    chars_in_burst += 1
        
        return ''.join(result)
    
    def generate_weighted_letter_sequence(self, target_length):
        """Generate letters with weighted probability for maximum uncommonness"""
        sequence = []
        for _ in range(target_length + 5):  # Extra letters for flexibility
            rand = random.random()
            if rand < 0.3:  # 30% ultra rare
                sequence.append(random.choice(self.ultra_rare_letters))
            elif rand < 0.5:  # 20% rare
                sequence.append(random.choice(self.rare_letters))
            elif rand < 0.75:  # 25% uncommon
                sequence.append(random.choice(self.uncommon_letters))
            else:  # 25% medium
                sequence.append(random.choice(self.medium_letters))
        
        return ''.join(sequence)
    
    def insert_advanced_elements(self, text, target_length):
        """Insert symbols, numbers, and special elements with advanced patterns"""
        chars = list(text)
        insertions_made = 0
        max_insertions = target_length // 3  # Up to 1/3 can be special chars
        
        # Insert different types of special characters
        element_types = [
            ('unicode', lambda: random.choice(self.unicode_symbols)),
            ('hex', lambda: random.choice(self.hex_digits)),
            ('advanced_symbol', lambda: random.choice(self.advanced_symbols)),
            ('basic_symbol', lambda: random.choice(self.basic_symbols)),
            ('binary', lambda: random.choice(self.binary_digits)),
            ('number', lambda: str(random.randint(0, 9))),
        ]
        
        # Weighted insertion of different elements
        for element_type, generator in element_types:
            if insertions_made >= max_insertions or len(chars) >= target_length:
                break
                
            # Insert 1-2 of each type randomly
            for _ in range(random.randint(1, 2)):
                if len(chars) < target_length:
                    pos = random.randint(0, len(chars))
                    chars.insert(pos, generator())
                    insertions_made += 1
        
        return ''.join(chars)
    
    def apply_character_substitution(self, password):
        """Apply leetspeak and advanced character substitutions"""
        substitutions = {
            'a': ['@', '4', 'Å', 'α'],
            'A': ['@', '4', 'Å', 'Λ'],
            'e': ['3', '€', 'ë', 'ɛ'],
            'E': ['3', '€', 'Ë', 'Σ'],
            'i': ['1', '!', 'í', 'ï'],
            'I': ['1', '!', 'Í', '|'],
            'o': ['0', 'ø', 'ö', 'ω'],
            'O': ['0', 'Ø', 'Ö', 'Ω'],
            's': ['$', '5', 'ş', 'ß'],
            'S': ['$', '5', 'Ş', '§'],
            't': ['+', '7', 'ţ', '†'],
            'T': ['+', '7', 'Ţ', '†'],
        }
        
        password_list = list(password)
        # Apply substitutions to 20-30% of applicable characters
        substitution_rate = random.uniform(0.2, 0.3)
        
        for i, char in enumerate(password_list):
            if char in substitutions and random.random() < substitution_rate:
                password_list[i] = random.choice(substitutions[char])
        
        return ''.join(password_list)
    
    def ensure_complexity_requirements(self, password):
        """Ensure password meets all complexity requirements"""
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in self.all_symbols for c in password)
        
        password_list = list(password)
        
        if not has_upper:
            # Convert a random lowercase to uppercase
            lower_indices = [i for i, c in enumerate(password_list) if c.islower()]
            if lower_indices:
                idx = random.choice(lower_indices)
                password_list[idx] = password_list[idx].upper()
        
        if not has_lower:
            # Convert a random uppercase to lowercase
            upper_indices = [i for i, c in enumerate(password_list) if c.isupper()]
            if upper_indices:
                idx = random.choice(upper_indices)
                password_list[idx] = password_list[idx].lower()
        
        if not has_digit:
            # Replace a random character with a digit
            idx = random.randint(0, len(password_list) - 1)
            password_list[idx] = str(random.randint(0, 9))
        
        if not has_symbol:
            # Replace a random character with a symbol
            idx = random.randint(0, len(password_list) - 1)
            password_list[idx] = random.choice(self.basic_symbols)
        
        return ''.join(password_list)
    
    def calculate_entropy(self, password):
        """Calculate password entropy for strength measurement"""
        charset_size = 0
        
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in self.basic_symbols for c in password):
            charset_size += len(self.basic_symbols)
        if any(c in self.advanced_symbols for c in password):
            charset_size += len(self.advanced_symbols)
        if any(c in self.unicode_symbols for c in password):
            charset_size += len(self.unicode_symbols)
        
        import math
        entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0
        return round(entropy, 2)
    
    def analyze_pattern_complexity(self, password):
        """Analyze various complexity patterns in the password"""
        analysis = {
            'consecutive_chars': 0,
            'repeated_chars': 0,
            'pattern_breaks': 0,
            'charset_diversity': 0,
            'position_entropy': 0
        }
        
        # Count consecutive identical characters
        consecutive = 1
        max_consecutive = 1
        for i in range(1, len(password)):
            if password[i] == password[i-1]:
                consecutive += 1
                max_consecutive = max(max_consecutive, consecutive)
            else:
                consecutive = 1
        analysis['consecutive_chars'] = max_consecutive
        
        # Count character frequency
        char_freq = Counter(password)
        analysis['repeated_chars'] = sum(1 for count in char_freq.values() if count > 1)
        
        # Count pattern breaks (case changes, type changes)
        for i in range(1, len(password)):
            prev_type = self.get_char_type(password[i-1])
            curr_type = self.get_char_type(password[i])
            if prev_type != curr_type:
                analysis['pattern_breaks'] += 1
        
        # Calculate charset diversity
        charsets = set()
        for char in password:
            charsets.add(self.get_char_type(char))
        analysis['charset_diversity'] = len(charsets)
        
        return analysis
    
    def get_char_type(self, char):
        """Determine character type for pattern analysis"""
        if char.islower():
            return 'lowercase'
        elif char.isupper():
            return 'uppercase'
        elif char.isdigit():
            return 'digit'
        elif char in self.basic_symbols:
            return 'basic_symbol'
        elif char in self.advanced_symbols:
            return 'advanced_symbol'
        elif char in self.unicode_symbols:
            return 'unicode_symbol'
        else:
            return 'other'
    
    def generate_ultra_password(self, length=18, complexity_level='maximum'):
        """Generate ultra-complex password with multiple enhancement layers"""
        # Step 1: Generate base sequence with weighted uncommon letters
        base_sequence = self.generate_weighted_letter_sequence(length)
        
        # Step 2: Apply complex case patterns
        case_pattern = random.choice(self.complexity_patterns)
        case_complex = self.apply_ultra_case_complexity(base_sequence, case_pattern)
        
        # Step 3: Insert advanced elements (symbols, numbers, unicode)
        with_elements = self.insert_advanced_elements(case_complex, length)
        
        # Step 4: Apply character substitutions
        if complexity_level in ['high', 'maximum']:
            with_substitutions = self.apply_character_substitution(with_elements)
        else:
            with_substitutions = with_elements
        
        # Step 5: Ensure exact length
        final_password = self.truncate_to_length(with_substitutions, length)
        
        # Step 6: Ensure all complexity requirements are met
        final_password = self.ensure_complexity_requirements(final_password)
        
        # Step 7: Final validation and adjustment
        if complexity_level == 'maximum':
            # Additional scrambling for maximum security
            final_password = self.apply_final_scramble(final_password)
        
        return final_password
    
    def apply_final_scramble(self, password):
        """Apply final scrambling for maximum complexity"""
        password_list = list(password)
        
        # Randomly swap 2-3 pairs of characters
        for _ in range(random.randint(2, 3)):
            if len(password_list) >= 2:
                i, j = random.sample(range(len(password_list)), 2)
                password_list[i], password_list[j] = password_list[j], password_list[i]
        
        return ''.join(password_list)
    
    def truncate_to_length(self, password, target_length):
        """Smart truncation/padding to exact length"""
        if len(password) > target_length:
            return password[:target_length]
        elif len(password) < target_length:
            # Pad with diverse elements
            padding_options = [
                lambda: random.choice(self.ultra_rare_letters),
                lambda: random.choice(self.all_symbols),
                lambda: str(random.randint(0, 9)),
                lambda: random.choice(self.unicode_symbols)
            ]
            
            while len(password) < target_length:
                padding_func = random.choice(padding_options)
                password += padding_func()
        
        return password
    
    def get_password_length(self):
        """Get password length from user (15-20 characters)"""
        while True:
            try:
                length = input("Enter password length (15-20, default 18): ").strip()
                if not length:
                    return 18
                
                length = int(length)
                if 15 <= length <= 20:
                    return length
                else:
                    print("❌ Please enter a length between 15 and 20 characters.")
            except ValueError:
                print("❌ Please enter a valid number.")
    
    def get_complexity_level(self):
        """Get desired complexity level from user"""
        print("\nComplexity Levels:")
        print("1. Standard - Basic uncommon letters + symbols")
        print("2. High - + Character substitutions + Advanced symbols")
        print("3. Maximum - + Unicode symbols + Final scrambling")
        
        while True:
            choice = input("Select complexity level (1-3, default 3): ").strip()
            if not choice or choice == '3':
                return 'maximum'
            elif choice == '1':
                return 'standard'
            elif choice == '2':
                return 'high'
            else:
                print("❌ Please select 1, 2, or 3.")
    
    def generate_multiple_passwords(self, count=5, length=18, complexity='maximum'):
        """Generate multiple ultra-complex passwords"""
        passwords = []
        for i in range(count):
            password = self.generate_ultra_password(length, complexity)
            passwords.append(password)
        return passwords
    
    def calculate_crack_time(self, password):
        """Calculate time to crack password using different attack methods"""
        # Estimate character set size
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in self.basic_symbols for c in password):
            charset_size += len(self.basic_symbols)
        if any(c in self.advanced_symbols for c in password):
            charset_size += len(self.advanced_symbols)
        if any(c in self.unicode_symbols for c in password):
            charset_size += len(self.unicode_symbols)
        
        # Total possible combinations
        total_combinations = charset_size ** len(password)
        
        # Average attempts needed (50% of search space)
        avg_attempts = total_combinations // 2
        
        # Different attack scenarios (attempts per second)
        attack_scenarios = {
            'Online Attack (slow)': 100,  # 100 attempts/sec (rate limited)
            'Online Attack (fast)': 10000,  # 10K attempts/sec
            'Offline MD5/SHA1': 1000000000,  # 1 billion/sec (GPU)
            'Offline bcrypt': 100000,  # 100K/sec (designed to be slow)
            'Offline Advanced GPU': 10000000000,  # 10 billion/sec (high-end GPU farm)
            'Quantum Computer': 1000000000000  # 1 trillion/sec (theoretical)
        }
        
        crack_times = {}
        for scenario, rate in attack_scenarios.items():
            seconds = avg_attempts / rate
            crack_times[scenario] = self.format_time_duration(seconds)
        
        return crack_times, total_combinations
    
    def format_time_duration(self, seconds):
        """Convert seconds to human-readable time format"""
        if seconds < 1:
            return "Instantly"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        elif seconds < 31536000000:
            return f"{seconds/31536000:.1f} years"
        elif seconds < 31536000000000:
            return f"{seconds/31536000000:.1f} thousand years"
        elif seconds < 31536000000000000:
            return f"{seconds/31536000000000:.1f} million years"
        elif seconds < 31536000000000000000:
            return f"{seconds/31536000000000000:.1f} billion years"
        else:
            return f"{seconds/31536000000000000000:.1e} trillion+ years"
    
    def analyze_user_password(self, password):
        """Analyze user's own password for security assessment"""
        basic_analysis = {
            'length': len(password),
            'uppercase_count': sum(1 for c in password if c.isupper()),
            'lowercase_count': sum(1 for c in password if c.islower()),
            'digit_count': sum(1 for c in password if c.isdigit()),
            'basic_symbol_count': sum(1 for c in password if c in self.basic_symbols),
            'advanced_symbol_count': sum(1 for c in password if c in self.advanced_symbols),
            'unicode_symbol_count': sum(1 for c in password if c in self.unicode_symbols),
            'entropy': self.calculate_entropy(password)
        }
        
        pattern_analysis = self.analyze_pattern_complexity(password)
        crack_times, total_combinations = self.calculate_crack_time(password)
        
        # Combine all analyses
        basic_analysis.update(pattern_analysis)
        basic_analysis['crack_times'] = crack_times
        basic_analysis['total_combinations'] = total_combinations
        
        # Calculate overall strength score (0-100)
        strength_score = min(100, (
            basic_analysis['entropy'] * 0.4 +
            basic_analysis['charset_diversity'] * 10 +
            basic_analysis['pattern_breaks'] * 2 +
            (100 - basic_analysis['consecutive_chars'] * 10) +
            (100 - basic_analysis['repeated_chars'] * 5)
        ))
        
        basic_analysis['strength_score'] = round(max(0, strength_score), 1)
        
        return basic_analysis
    
    def analyze_ultra_password_strength(self, password):
        """Comprehensive password strength analysis for generated passwords"""
        return self.analyze_user_password(password)

def main():
    print("🚀 ULTRA ADVANCED PASSWORD GENERATOR 🚀")
    print("=" * 70)
    print("💪 Maximum complexity with uncommon letters, unicode symbols, and advanced patterns")
    
    generator = UltraAdvancedPasswordGenerator()
    
    while True:
        print("\n" + "="*50)
        print("Options:")
        print("1. Generate single ultra-complex password")
        print("2. Generate multiple ultra-complex passwords")
        print("3. Generate and analyze password strength")
        print("4. Analyze YOUR password (crack time estimation)")
        print("5. Exit")
        
        choice = input("\nSelect option (1-5): ").strip()
        
        if choice == '1':
            length = generator.get_password_length()
            complexity = generator.get_complexity_level()
            password = generator.generate_ultra_password(length, complexity)
            print(f"\n🔐 Generated {complexity.upper()} complexity password ({length} chars):")
            print(f"🔑 {password}")
            
        elif choice == '2':
            length = generator.get_password_length()
            complexity = generator.get_complexity_level()
            try:
                count = int(input("How many passwords to generate (default 5): ") or "5")
                passwords = generator.generate_multiple_passwords(count, length, complexity)
                print(f"\n🔐 Generated {count} {complexity.upper()} complexity passwords ({length} chars each):")
                for i, pwd in enumerate(passwords, 1):
                    print(f"{i:2d}. {pwd}")
            except ValueError:
                print("❌ Please enter a valid number")
                
        elif choice == '3':
            length = generator.get_password_length()
            complexity = generator.get_complexity_level()
            password = generator.generate_ultra_password(length, complexity)
            analysis = generator.analyze_ultra_password_strength(password)
            
            print(f"\n🔐 Generated {complexity.upper()} complexity password ({length} chars):")
            print(f"🔑 {password}")
            print("\n📊 COMPREHENSIVE PASSWORD ANALYSIS:")
            print(f"├─ Length: {analysis['length']} characters")
            print(f"├─ Entropy: {analysis['entropy']} bits")
            print(f"├─ Strength Score: {analysis['strength_score']}/100")
            print(f"├─ Character Distribution:")
            print(f"│  ├─ Uppercase: {analysis['uppercase_count']}")
            print(f"│  ├─ Lowercase: {analysis['lowercase_count']}")
            print(f"│  ├─ Digits: {analysis['digit_count']}")
            print(f"│  ├─ Basic symbols: {analysis['basic_symbol_count']}")
            print(f"│  ├─ Advanced symbols: {analysis['advanced_symbol_count']}")
            print(f"│  └─ Unicode symbols: {analysis['unicode_symbol_count']}")
            print(f"├─ Pattern Complexity:")
            print(f"│  ├─ Charset diversity: {analysis['charset_diversity']}/6")
            print(f"│  ├─ Pattern breaks: {analysis['pattern_breaks']}")
            print(f"│  ├─ Max consecutive chars: {analysis['consecutive_chars']}")
            print(f"│  └─ Repeated characters: {analysis['repeated_chars']}")
            
            # Show crack time estimates for generated passwords too
            print(f"└─ Crack Time Estimates:")
            for scenario, time_str in analysis['crack_times'].items():
                if 'bcrypt' in scenario or 'Online Attack (slow)' in scenario:
                    print(f"   ├─ {scenario}: {time_str}")
            
            # Security rating
            if analysis['strength_score'] >= 90:
                rating = "🛡️  ULTRA SECURE"
            elif analysis['strength_score'] >= 80:
                rating = "🔒 VERY SECURE"
            elif analysis['strength_score'] >= 70:
                rating = "🔐 SECURE"
            else:
                rating = "⚠️  MODERATE"
            print(f"└─ Security Rating: {rating}")
            
        elif choice == '4':
            print("\n🔍 PASSWORD CRACK TIME ANALYZER")
            print("⚠️  Enter your password to analyze (input will be hidden for security)")
            print("💡 This tool estimates how long it would take to crack your password if someone steals the hash")
            
            import getpass
            try:
                user_password = getpass.getpass("Enter your password: ")
                if not user_password:
                    print("❌ No password entered.")
                    continue
                    
                print(f"\n🔐 Analyzing password (length: {len(user_password)} characters)...")
                analysis = generator.analyze_user_password(user_password)
                
                print(f"\n📊 PASSWORD SECURITY ANALYSIS:")
                print(f"├─ Length: {analysis['length']} characters")
                print(f"├─ Entropy: {analysis['entropy']} bits")
                print(f"├─ Strength Score: {analysis['strength_score']}/100")
                print(f"├─ Total Possible Combinations: {analysis['total_combinations']:,}")
                
                print(f"├─ Character Distribution:")
                print(f"│  ├─ Uppercase: {analysis['uppercase_count']}")
                print(f"│  ├─ Lowercase: {analysis['lowercase_count']}")
                print(f"│  ├─ Digits: {analysis['digit_count']}")
                print(f"│  ├─ Basic symbols: {analysis['basic_symbol_count']}")
                print(f"│  ├─ Advanced symbols: {analysis['advanced_symbol_count']}")
                print(f"│  └─ Unicode symbols: {analysis['unicode_symbol_count']}")
                
                print(f"└─ Pattern Complexity:")
                print(f"   ├─ Charset diversity: {analysis['charset_diversity']}/6")
                print(f"   ├─ Pattern breaks: {analysis['pattern_breaks']}")
                print(f"   ├─ Max consecutive chars: {analysis['consecutive_chars']}")
                print(f"   └─ Repeated characters: {analysis['repeated_chars']}")
                
                print(f"\n⏱️  CRACK TIME ESTIMATES (if hash is stolen):")
                print("="*60)
                for scenario, time_str in analysis['crack_times'].items():
                    if 'Online' in scenario:
                        emoji = "🌐"
                    elif 'bcrypt' in scenario:
                        emoji = "🛡️ "
                    elif 'Quantum' in scenario:
                        emoji = "🔬"
                    elif 'Advanced GPU' in scenario:
                        emoji = "💻"
                    else:
                        emoji = "⚡"
                    
                    print(f"{emoji} {scenario:<25}: {time_str}")
                
                # Security recommendations
                print(f"\n💡 SECURITY RECOMMENDATIONS:")
                if analysis['strength_score'] >= 90:
                    print("✅ Excellent! Your password is very strong.")
                elif analysis['strength_score'] >= 80:
                    print("✅ Good! Your password is strong.")
                elif analysis['strength_score'] >= 70:
                    print("⚠️  Decent, but could be stronger.")
                    print("   Consider adding more special characters or increasing length.")
                else:
                    print("❌ Weak! Your password needs improvement.")
                    print("   Recommendations:")
                    if analysis['length'] < 12:
                        print("   • Increase length to at least 12+ characters")
                    if analysis['charset_diversity'] < 4:
                        print("   • Add more character types (uppercase, symbols, numbers)")
                    if analysis['consecutive_chars'] > 2:
                        print("   • Avoid consecutive identical characters")
                    if analysis['pattern_breaks'] < analysis['length'] // 3:
                        print("   • Mix character types more frequently")
                
                print(f"\n🔐 HASH STORAGE SECURITY:")
                print("• Use bcrypt, scrypt, or Argon2 for password hashing")
                print("• Avoid MD5, SHA1, or plain SHA256 for passwords")
                print("• Enable 2FA whenever possible")
                
            except KeyboardInterrupt:
                print("\n❌ Password analysis cancelled.")
            except Exception as e:
                print(f"❌ Error analyzing password: {e}")
            
        elif choice == '5':
            print("\n🎉 Thank you for using Ultra Advanced Password Generator!")
            print("Stay secure! 🔐")
            break
            
        else:
            print("❌ Invalid option. Please select 1-5.")

if __name__ == "__main__":
    main()

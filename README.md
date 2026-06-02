import re
import math
from collections import Counter


class PasswordAnalyzer:
    def __init__(self, password):
        self.password = password

    def entropy(self):
        charset = 0

        if re.search(r"[a-z]", self.password):
            charset += 26

        if re.search(r"[A-Z]", self.password):
            charset += 26

        if re.search(r"\d", self.password):
            charset += 10

        if re.search(r"[^a-zA-Z0-9]", self.password):
            charset += 32

        if charset == 0:
            return 0

        return round(len(self.password) * math.log2(charset), 2)

    def score(self):
        score = 0

        if len(self.password) >= 8:
            score += 20

        if len(self.password) >= 12:
            score += 20

        if re.search(r"[a-z]", self.password):
            score += 15

        if re.search(r"[A-Z]", self.password):
            score += 15

        if re.search(r"\d", self.password):
            score += 15

        if re.search(r"[^a-zA-Z0-9]", self.password):
            score += 15

        common_patterns = [
            "123456",
            "password",
            "qwerty",
            "admin",
            "welcome"
        ]

        for pattern in common_patterns:
            if pattern.lower() in self.password.lower():
                score -= 30

        return max(0, min(score, 100))

    def strength(self):
        score = self.score()

        if score < 30:
            return "Very Weak"

        if score < 50:
            return "Weak"

        if score < 70:
            return "Moderate"

        if score < 90:
            return "Strong"

        return "Very Strong"

    def suggestions(self):
        tips = []

        if len(self.password) < 12:
            tips.append("Use at least 12 characters")

        if not re.search(r"[A-Z]", self.password):
            tips.append("Add uppercase letters")

        if not re.search(r"[a-z]", self.password):
            tips.append("Add lowercase letters")

        if not re.search(r"\d", self.password):
            tips.append("Add numbers")

        if not re.search(r"[^a-zA-Z0-9]", self.password):
            tips.append("Add special characters")

        return tips

    def repeated_characters(self):
        counter = Counter(self.password)

        return {
            char: count
            for char, count in counter.items()
            if count > 2
        }

    def report(self):
        print("\n" + "=" * 50)
        print("PASSWORD ANALYSIS REPORT")
        print("=" * 50)

        print(f"Length      : {len(self.password)}")
        print(f"Entropy     : {self.entropy()} bits")
        print(f"Score       : {self.score()}/100")
        print(f"Strength    : {self.strength()}")

        repeats = self.repeated_characters()

        if repeats:
            print(f"Repeats     : {repeats}")

        suggestions = self.suggestions()

        if suggestions:
            print("\nSuggestions:")
            for tip in suggestions:
                print(f" - {tip}")

        print("=" * 50)


def main():
    password = input("Enter password: ")

    analyzer = PasswordAnalyzer(password)

    analyzer.report()


if __name__ == "__main__":
    main()

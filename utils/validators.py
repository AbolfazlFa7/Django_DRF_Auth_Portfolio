import re
from string import ascii_lowercase, ascii_uppercase, punctuation, digits
from django.core.exceptions import ValidationError


def normalize_email(email: str):
    """
    - strip whitespaces
    - lower case the domin part of the email
    - detact the Gmail Dot Trick, and fix it

    example:
            'Abc.def@Gmail.com' --> 'Abcdef@gmail.com' 
            'Abcdef@Gma.il.com' --> raise ValueError
    """
    email = email.lower().strip()

    reversed_email = email[::-1]
    suffix, prefix = re.findall(r'(.*?\..*?@)(.*)', reversed_email)[0]
    prefix = prefix.replace('.', '')
    normalized_email = prefix[::-1] + suffix[::-1]

    if normalized_email.count('.') > 1:
        raise ValidationError('Your email is not in the correct format')

    return normalized_email


def validate_password(password: str):
    """
    - at least 8 characters
    - contains at least one of each of the following:
        - UpperCase
        - LowerCase
        - Digit
        - Punctuation mark  

    example: 
    A12345a@   -> pass
    A12345a    -> fail
    """
    if 20 >= len(password) >= 8:
        if all([
            bool(set(ascii_lowercase) & set(password)),
            bool(set(ascii_uppercase) & set(password)),
            bool(set(punctuation) & set(password)),
            bool(set(digits) & set(password))
        ]):

            return password
        else:
            raise ValidationError(
                'Password must contain at least one charater from each of "UpperCase" and "LowerCase" and "Digit" and "Punctuation mark".')
    else:
        raise ValidationError('Password must be at least 8 characters long')


def validate_phone(phone: str):
    phone = re.findall(r'^(\+98|0)?(9\d{9})$', phone)
    if phone:
        phone = '0' + phone[0][1]
        return phone
    else:
        raise ValidationError(
            'Invalid Phone Number, must follow this pattern: +989123456789 or 09123456789')

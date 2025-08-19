from faker import Faker
import toml
import argparse
import sys
import psycopg2
import random
import base58
import os
from substrateinterface import Keypair

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def generate_timeline(conn, networks, config):
    if not args.__dict__.get("generate_timeline"):
        return

    cursor = conn.cursor()

    size = args.__dict__.get("timeline_size")
    cursor.execute(f'''SELECT (wallet_id, network) FROM registration ORDER BY RANDOM() LIMIT {size};''')

    results = cursor.fetchall()

    for result in results:

        end_date = fake.date_time_this_year(before_now=True)
        start_date = fake.date_time_between(end_date=end_date, start_date="-1y")
        result = tuple(result[0][1:-1].split(sep=","))

        print(f"START DATE {bcolors.OKBLUE}{start_date}{bcolors.ENDC} EVENT {bcolors.OKGREEN}created{bcolors.ENDC}")

        cursor.execute(f'''SELECT (wallet_id) FROM timeline_elem WHERE wallet_id=%s AND network=%s AND EVENT=%s;''', (result[0], result[1], "created"))
        if len(cursor.fetchall()) > 0:
            print(f"{bcolors.FAIL}SKIPPING ({result[0]}, {result[1]}, 'created') {bcolors.ENDC}")
            continue

        cursor.execute('''INSERT INTO timeline_elem (wallet_id, network, EVENT, date) VALUES (%s, %s, %s, %s);''', (result[0], result[1], "created", start_date))
        steps = random.randint(1,4)
        events = random.sample(["discord", "display", "email", "twitter", "github", "web", "matrix", "pgp_fingerprint"], steps)
        for event in events:
            between = fake.date_time_between_dates(datetime_start=start_date)
            cursor.execute(f'''SELECT (wallet_id) FROM timeline_elem WHERE wallet_id=%s AND network=%s AND EVENT=%s;''', (result[0], result[1], event))
            if len(cursor.fetchall()) > 0:
                print(f"{bcolors.FAIL}SKIPPING ({result[0]}, {result[1]}, {event}){bcolors.ENDC}", )
                continue

            print(f"BETWEEN DATE {bcolors.OKCYAN}{between}{bcolors.ENDC} EVENT {bcolors.OKGREEN}{event}{bcolors.ENDC}")
            cursor.execute('''INSERT INTO timeline_elem (wallet_id, network, EVENT, date) VALUES (%s, %s, %s, %s);''', (result[0], result[1], event, between))

        print(f"END DATE {bcolors.WARNING}{end_date}{bcolors.ENDC} EVENT {bcolors.OKGREEN}verified{bcolors.ENDC}")
        cursor.execute('''INSERT INTO timeline_elem (wallet_id, network, EVENT, date) VALUES (%s, %s, %s, %s);''', (result[0], result[1], "verified", end_date))

    print(f"{bcolors.HEADER}COMITTING ....{bcolors.ENDC}")
    conn.commit()
    

def generate_registration(conn,networks, config):
    if not args.__dict__.get("generate_registrations"):
        return

    cursor = conn.cursor()

    for _ in range(args.__dict__.get("registrations_size")):
        mnemonic = Keypair.generate_mnemonic()
        keypair = Keypair.create_from_mnemonic(mnemonic)
        network = random.choice(networks)
        
        wallet_id = keypair.ss58_address
        discord = fake.user_name()
        twitter = fake.user_name()
        matrix = f'@{fake.user_name()}:matrix.org'
        email = fake.email()
        display = fake.name()
        github = fake.user_name()
        legal = display
        web = fake.domain_name()
        #pgp_fingerprint = ''.join(random.choices('0123456789ABCDEF', k=40))
        
        print(f"{bcolors.OKBLUE}wallet_id: {wallet_id}{bcolors.ENDC}")
        print(f"{bcolors.OKBLUE}email: {email}{bcolors.ENDC}")
        print(f"{bcolors.OKBLUE}discord: {discord}{bcolors.ENDC}")
        print(f"{bcolors.OKBLUE}twitter: {twitter}{bcolors.ENDC}")
        print(f"{bcolors.OKBLUE}display: {display}{bcolors.ENDC}")
        print(f"{bcolors.OKBLUE}network: {network}{bcolors.ENDC}")
        print(f"{bcolors.WARNING}=============================={bcolors.ENDC}")

        row = (wallet_id, network, discord, twitter, matrix, email, display, github, legal, web)
        cursor.execute(
            '''INSERT INTO registration (wallet_id, network, discord, twitter, matrix, email, display_name, github, legal, web)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ;''',
            row
        )

    print(f"{bcolors.HEADER}COMITTING ....{bcolors.ENDC}")
    conn.commit()

fake = Faker()


def registrations(conn, size = 10):
    cursor = conn.cursor()

    cursor.execute(f'''SELECT (wallet_id, network, discord, twitter, email, display_name) FROM registration LIMIT {size};''')
    results = cursor.fetchall()

    for result in results:
        print(result)

def read_args():
    parser = argparse.ArgumentParser(description='Data population for w3registrar postgres DB')
    parser.add_argument('--config', type=str, required=True, help='config.toml file path')
    parser.add_argument('--generate-registrations', type=bool, help='generate registration data (bool)', default=False)
    parser.add_argument('--generate-timeline', type=bool, help='generate timeline data (bool)', default=False)
    parser.add_argument('--registrations-size', type=int, help='size of the generated registration data (int)', default=50)
    parser.add_argument('--timeline-size', type=int, help='size of the generated timeline data (int)', default=10)
    args = parser.parse_args()
    return args

def read_config(path):
    return toml.load(path)

def connect_postgres(config):
    config=config["postgres"]

    if config.get("cert_path"): 
        ssl_params = {
            "sslmode": "require",
            "sslkey": config.get("cert_path"),
        }
    else:
        ssl_params = {}

    print(f"{bcolors.OKGREEN}CONNECTING...{bcolors.ENDC}")

    conn = psycopg2.connect(host=config.get("host"),
                            database=config.get("dbname"),
                            user=config.get("user"),
                            password=config.get("password"),
                            port=config.get("port"),
                            **ssl_params)

    print(f"{bcolors.OKGREEN}CONNECTED{bcolors.ENDC}")

    return conn

networks = ["polkadot", "paseo", "rococo", "kusama"]
args = read_args()
config = read_config(args.config)
conn = connect_postgres(config)
# registrations(conn)
generate_registration(conn, networks, conn)
generate_timeline(conn, networks, conn)
conn.close()

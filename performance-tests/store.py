import argparse
import json
import os
import uuid

from opensearchpy import OpenSearch


def main(args):
    host = os.environ.get('OPENSEARCH_HOST')
    auth = (
        os.environ.get('OPENSEARCH_USER'),
        os.environ.get('OPENSEARCH_PASSWORD')
    )

    client = OpenSearch(
        hosts=[{"host": host, "port": 443}],
        http_auth=auth,
        http_compress=True,
        use_ssl=True,
        verify_certs=True,
        ssl_assert_hostname=False,
        ssl_show_warn=False,
    )

    with open(args.result, 'r') as f:
        document = json.load(f)

        response = client.index(
            index = args.index,
            body = document,
            id = uuid.uuid4(),
            refresh = True
        )


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='store')
    parser.add_argument('result', help='Path to the data file to store')
    parser.add_argument('index', help='OpenSearch index to store the data')

    args = parser.parse_args()

    main(args)

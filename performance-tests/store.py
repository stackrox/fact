import argparse
import json
import os
import uuid
import numpy as np

from opensearchpy import OpenSearch


def main(args):
    host = os.environ.get('K6_ELASTICSEARCH_URL')
    auth = (
        os.environ.get('K6_ELASTICSEARCH_USER'),
        os.environ.get('K6_ELASTICSEARCH_PASSWORD')
    )

    if not (host and auth[0] and auth[1]):
        print("No credentials provided")
        return

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
        documents = json.load(f)

        for document in documents:
            if type(document['value']) is list:
                values = document['value']
                d = document.copy()

                d['value'] = np.percentile(values, 90).item()
                d['unit'] = "{}, 90p".format(document['unit'])

                response = client.index(
                    index = args.index,
                    body = d,
                    id = uuid.uuid4(),
                    refresh = True
                )

                d['value'] = np.percentile(values, 50).item()
                d['unit'] = "{}, median".format(document['unit'])

                response = client.index(
                    index = args.index,
                    body = d,
                    id = uuid.uuid4(),
                    refresh = True
                )

            else:
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

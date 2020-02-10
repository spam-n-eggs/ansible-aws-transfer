FROM python:3

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "python", "./ansible_collections/spam_n_eggs/amazon/plugins/modules/transfer_user_credentials.py", "args.json"]

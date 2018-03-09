from flask import Flask, redirect, render_template, request, session
import yaml
import requests
import json
import collections
from Bio import Entrez
from mendeley import Mendeley
from mendeley.session import MendeleySession


with open('config.yml') as f:
    config = yaml.load(f)

REDIRECT_URI = 'http://127.0.0.1:5000/oauth'

app = Flask(__name__)
app.debug = True
app.secret_key = config['clientSecret']

mendeley = Mendeley(config['clientId'], config['clientSecret'], REDIRECT_URI)

#convert doi to pmid
def doi_to_pmid(doi, email):
    pmid = ''
    r = requests.get('https://www.ncbi.nlm.nih.gov/pmc/utils/idconv/v1.0/?ids='+doi+'&format=json&email='+email)
    data_json = r.json()
    if 'records' in data_json:
        record = data_json['records'][0]
        if 'pmid' in record:
            pmid = record['pmid']
    return pmid

#get pmid from docs
def check_pmid(doc, email):
    if doc.identifiers is not None:
        if 'pmid' in doc.identifiers:
            return doc.identifiers['pmid']
        elif 'doi' in doc.identifiers and 'pmid' not in doc.identifiers:
            try:
                conversion = doi_to_pmid(doc.identifiers['doi'], email)
                if conversion != '' and conversion != None:
                    return conversion
                else:
                    cat = mendeley_session.catalog.lookup(doi=doc.identifiers['doi'])
                    if 'pmid' in cat.identifiers:
                        return cat.identifiers['pmid']
                    else:
                        return doc.identifiers['doi']
            except:
                return doc.identifiers['doi']
    else:
        return ' '

def get_linked_pmids(pmids, email):
    Entrez.email = email
    handle = Entrez.elink(id=pmids, db='pubmed', dbfrom='pubmed', retmode='json', linkname='pubmed_pubmed')
    json_text = handle.read()
    links = json.loads(json_text)
    ids = []
    for l in links['linksets']:
        ids.extend(l['linksetdbs'][0]['links'])
    p = [int(pmids) for pmids in pmids]
    ids_removed = [item for item in ids if item not in p]
    counter=collections.Counter(ids_removed)
    most_common_pmids = counter.most_common(100)
    return most_common_pmids

@app.route('/')
def home():
    if 'token' in session:
        return redirect('/listDocuments')

    auth = mendeley.start_authorization_code_flow()
    session['state'] = auth.state

    return render_template('home.html', login_url=(auth.get_login_url()))


@app.route('/oauth')
def auth_return():
    auth = mendeley.start_authorization_code_flow(state=session['state'])
    mendeley_session = auth.authenticate(request.url)

    session.clear()
    session['token'] = mendeley_session.token

    return redirect('/listDocuments')


@app.route('/listDocuments')
def list_documents():
    if 'token' not in session:
        return redirect('/')

    mendeley_session = get_session_from_cookies()

    name = mendeley_session.profiles.me.display_name
    groups = mendeley_session.groups.list().items

    return render_template('library.html', name=name, groups=groups)

@app.route('/group')
def get_group():
    if 'token' not in session:
        return redirect('/')

    mendeley_session = get_session_from_cookies()

    group_id = request.args.get('group_id')
    group = mendeley_session.groups.get(group_id)
    email = mendeley_session.profiles.me.email

    pmids = []
    for doc in group.documents.iter():
        pmids.append(check_pmid(doc, email))
    urls = []
    for pmid in pmids:
        if len(pmid) == 8:
            urls.append('https://www.ncbi.nlm.nih.gov/pubmed/' + str(pmid))
        elif len(pmid) > 8:
            urls.append('https://doi.org/'+str(pmid))
        else:
            urls.append(' ')

    return render_template('group.html', group=group, pmids=pmids, urls=urls)


@app.route('/suggest')
def suggest():
    if 'token' not in session:
        return redirect('/')

    mendeley_session = get_session_from_cookies()
    group_id = request.args.get('group_id')
    group = mendeley_session.groups.get(group_id)
    email = mendeley_session.profiles.me.email

    pmids = []
    for doc in group.documents.iter():
        pmids.append(check_pmid(doc, email))

    p = []
    urls = []
    for pmid in pmids:
        if len(pmid) == 8:
            p.append(pmid)

    suggested_pmids = get_linked_pmids(p, email)

    catalog_lookup = []
    for pmid in suggested_pmids:
        try:
            pmid = str(pmid[0])
            urls.append('https://www.ncbi.nlm.nih.gov/pubmed/' + str(pmid))
            catalog_lookup.append(mendeley_session.catalog.lookup(pmid=pmid))
        except:
            catalog_lookup.append(' ')

    return render_template('suggest.html', group=group, catalog_lookup=catalog_lookup, suggested_pmids=suggested_pmids, urls=urls)

@app.route('/document')
def get_document():
    if 'token' not in session:
        return redirect('/')

    mendeley_session = get_session_from_cookies()

    document_id = request.args.get('document_id')
    pmid = request.args.get('pmid')

    try:
        doc = mendeley_session.documents.get(id=document_id)
    except:
        try:
            doc = mendeley_session.catalog.lookup(pmid=pmid)
        except:
            doc = ''

    return render_template('metadata.html', doc=doc)


@app.route('/metadataLookup')
def metadata_lookup():
    if 'token' not in session:
        return redirect('/')

    mendeley_session = get_session_from_cookies()

    doi = request.args.get('doi')
    doc = mendeley_session.catalog.by_identifier(doi=doi)

    return render_template('metadata.html', doc=doc)


@app.route('/download')
def download():
    if 'token' not in session:
        return redirect('/')

    mendeley_session = get_session_from_cookies()

    document_id = request.args.get('document_id')
    doc = mendeley_session.documents.get(document_id)
    doc_file = doc.files.list().items[0]

    return redirect(doc_file.download_url)


@app.route('/logout')
def logout():
    session.pop('token', None)
    return redirect('/')


def get_session_from_cookies():
    return MendeleySession(mendeley, session['token'])


if __name__ == '__main__':
    app.run()

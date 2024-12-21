#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <regex>
#include <curl/curl.h>
#include <thread>
#include <mutex>

using namespace std;

// Fonction de callback pour écrire la réponse dans une string
size_t WriteCallback(void* contents, size_t size, size_t nmemb, string* output) {
    size_t totalSize = size * nmemb;
    output->append((char*)contents, totalSize);
    return totalSize;
}

// Fonction pour envoyer une requête HTTP GET
string sendRequest(const string& url) {
    CURL* curl;
    CURLcode res;
    string response;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            cerr << "Erreur cURL: " << curl_easy_strerror(res) << endl;
        }
        curl_easy_cleanup(curl);
    }
    return response;
}

// Fonction pour détecter les vulnérabilités XSS
bool detectXSS(const string& response, const string& sanitizedPayload) {
    regex scriptPattern("<script.*?>.*?" + sanitizedPayload + ".*?</script>", regex::icase);
    regex eventAttrPattern("(on\\w+\\s*=\\s*['\"]?.*?" + sanitizedPayload + ".*?['\"]?)", regex::icase);
    regex htmlInjectionPattern("(<\\w+.*?\\s+(src|href|data|action)\\s*=\\s*['\"]?.*?" + sanitizedPayload + ".*?['\"]?.*?>)", regex::icase);
    regex encodedURLPattern("(%[0-9A-Fa-f]{2}|&#x[0-9A-Fa-f]+;).*?" + sanitizedPayload + ".*?", regex::icase);
    regex urlPattern("(javascript:|data:text/html|vbscript:).*?" + sanitizedPayload, regex::icase);

    return regex_search(response, scriptPattern) ||
           regex_search(response, eventAttrPattern) ||
           regex_search(response, htmlInjectionPattern) ||
           regex_search(response, encodedURLPattern) ||
           regex_search(response, urlPattern);
}

// Fonction pour charger les payloads depuis un fichier
vector<string> loadPayloads(const string& filename) {
    vector<string> payloads;
    ifstream file(filename);
    if (!file.is_open()) {
        cerr << "Erreur : Impossible d'ouvrir le fichier " << filename << endl;
        return payloads;
    }

    string line;
    while (getline(file, line)) {
        if (!line.empty()) {
            payloads.push_back(line);
        }
    }
    file.close();
    return payloads;
}

// Fonction pour extraire les liens présents sur une page HTML
vector<string> extractLinks(const string& html, const string& baseUrl) {
    vector<string> links;
    regex linkPattern("<a\\s+[^>]*href=[\"']([^\"']+)[\"']", regex::icase);
    auto linksBegin = sregex_iterator(html.begin(), html.end(), linkPattern);
    auto linksEnd = sregex_iterator();

    for (auto it = linksBegin; it != linksEnd; ++it) {
        string link = (*it)[1].str();

        // Si le lien est relatif, le compléter avec le baseUrl
        if (link.find("http://") == string::npos && link.find("https://") == string::npos) {
            if (baseUrl.back() == '/') {
                link = baseUrl + link;
            } else {
                link = baseUrl + "/" + link;
            }
        }
        links.push_back(link);
    }

    return links;
}

// Fonction pour injecter dans le dernier paramètre de l'URL
string injectIntoLastParam(const string& url, const string& payload) {
    size_t pos = url.find_last_of('&');
    if (pos != string::npos) {
        return url.substr(0, pos + 1) + url.substr(pos + 1) + payload;
    } else {
        return url + payload;
    }
}

// Fonction pour injecter des données dans la requête POST
string injectPostPayload(const string& url, const vector<string>& parameters, const string& payload) {
    string postData;
    for (const auto& param : parameters) {
        postData += param + "=" + payload + "&";
    }
    postData.pop_back(); // Enlever le dernier "&"
    
    CURL* curl;
    CURLcode res;
    string response;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            cerr << "Erreur cURL: " << curl_easy_strerror(res) << endl;
        }
        curl_easy_cleanup(curl);
    }

    return response;
}

// Fonction pour tester les XSS avec des threads
void testXSS(const string& method, const vector<string>& urls, const vector<string>& payloads, int threadCount) {
    // Utiliser un mutex pour protéger l'accès concurrent aux impressions
    mutex mtx;

    auto testFunc = [&](const string& url) {
        for (const auto& payload : payloads) {
            string response;
            string sanitizedPayload = regex_replace(payload, regex("[^\\w<>:/=+\"'&]"), "\\$&");

            {
                lock_guard<mutex> lock(mtx);
                cout << "[*] Test en cours sur " << url << " avec le payload : " << payload << endl;
            }

            if (method == "GET") {
                string testURL = injectIntoLastParam(url, payload);
                response = sendRequest(testURL);
            } else if (method == "POST") {
                string testURL = injectPostPayload(url, {"param1", "param2"}, payload); // Remplacez les paramètres selon le cas
                response = testURL;
            }

            if (detectXSS(response, sanitizedPayload)) {
                lock_guard<mutex> lock(mtx);
                cout << "[!] XSS détecté avec la méthode " << method << " sur " << url << " avec le payload : " << payload << endl;
            } else {
                lock_guard<mutex> lock(mtx);
                cout << "[OK] Pas de XSS détecté avec la méthode " << method << " sur " << url << " avec le payload : " << payload << endl;
            }
        }
    };

    vector<thread> threads;
    int urlsPerThread = urls.size() / threadCount;

    // Diviser les URLs entre les threads
    for (int i = 0; i < threadCount; ++i) {
        int startIdx = i * urlsPerThread;
        int endIdx = (i == threadCount - 1) ? urls.size() : (i + 1) * urlsPerThread;
        vector<string> subUrls(urls.begin() + startIdx, urls.begin() + endIdx);

        threads.emplace_back([=]() {
            for (const auto& url : subUrls) {
                testFunc(url);
            }
        });
    }

    // Attendre que tous les threads aient terminé
    for (auto& th : threads) {
        th.join();
    }
}

int main() {
    string url;
    int threadCount;
    
    cout << "Entrez l'URL cible : ";
    cin >> url;

    cout << "Entrez le nombre de threads : ";
    cin >> threadCount;

    // Charger les payloads depuis un fichier
    string payloadFile = "payloads.txt";
    vector<string> payloads = loadPayloads(payloadFile);

    if (payloads.empty()) {
        cerr << "Erreur : Aucun payload chargé depuis le fichier." << endl;
        return 1;
    }

    // Crawler l'URL cible
    cout << "[*] Crawling l'URL : " << url << endl;
    string html = sendRequest(url);
    vector<string> links = extractLinks(html, url);

    // Ajouter l'URL de départ dans les liens à tester
    links.push_back(url);

    cout << "[*] Liens détectés : " << links.size() << endl;
    for (const auto& link : links) {
        cout << " - " << link << endl;
    }

    // Tester les XSS sur tous les liens détectés
    cout << "\n[*] Test des XSS sur les liens..." << endl;
    testXSS("GET", links, payloads, threadCount);

    return 0;
}

Ce programme est un outil de test de vulnérabilités XSS (Cross-Site Scripting) automatisé, qui permet de scanner des sites Web pour détecter des failles de sécurité liées à l'injection de scripts malveillants. Il fonctionne en envoyant des requêtes HTTP (GET et POST) avec des payloads XSS pour analyser les réponses et vérifier la présence de vulnérabilités. Le programme supporte la gestion de multiples threads (jusqu'à 20 par défaut, avec la possibilité de personnaliser ce nombre) pour effectuer des tests parallèles, améliorant ainsi l'efficacité du scan. L'utilisateur peut fournir un fichier contenant des payloads et un lien URL cible, et l'outil se charge d'explorer les liens de la page pour tester chaque paramètre potentiel.

Fonctionnalités principales :

    Détection de vulnérabilités XSS via des requêtes GET et POST.
    Prise en charge des payloads définis dans un fichier texte.
    Exploration automatique des liens d'une page Web.
    Utilisation de threads pour paralléliser les tests et accélérer les scans.
    Possibilité de personnaliser le nombre de threads utilisés.


Compilation sous linux:

    sudo apt-get update
    sudo apt-get install libcurl4-openssl-dev g++ pthread
    g++  -o xss_scanner xss_scanner.cpp -lcurl -lpthread

Compilation sous Mac OS:

    brew install curl
    g++  -o xss_scanner xss_scanner.cpp -lcurl -lpthread

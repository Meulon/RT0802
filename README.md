# RT0802

- On dispose d’objets (véhicules) qui envoient deux types de messages CAM et DENM.
- On souhaite garantir l’authentification des objets.
- La passerelle recevait les messages et les renvoyait au centralisateur des événements.
- La passerelle contient une CA (un thread qui tourne par exemple) qui génère des certificats des clés publiques qui lui sont envoyées par les objets.
- Chaque objet possède le certificat autosigné du CA.
- Les objets envoient leurs message à la passerelle et s’arrangent pour que ceux ci soient authentifiés.
- 172.19.129.1

---
id: r26
title: Rencontre 26 - Injection SQL (attaque)
sidebar_label: R26 - Injection SQL (attaque)
draft: true
hide_table_of_contents: false
---

# Injecter du SQL

Une injection SQL c'est quoi?
- une situation où l'utilisateur peut exécuter du SQL de son choix sur la BD
- PAS LE PROGRAMMEUR mais l'utilisateur, nooooooooooonnnnnnnnnnn
- parce que le programmeur a pris ce que l'utilisateur lui a donné et l'a mélangé sans faire attention 
avec son code.


https://www.w3schools.com/sql/sql_injection.asp
## Pourquoi c'est rare mais très dangereux

Beaucoup d'attaques sont possibles parce qu'il faut faire un effort pour se protéger.

Pour les injections SQL, il faut programmer mal pour que ça arrive.

```
Les programmeurs paresseux sont très nombreux.
Les mauvais programmeurs sont moins nombreux.
Les mauvais programmeurs qui concatènent des données utilisateurs dans des requêtes SQL sont encore moins nombreux.
```

Par contre, quand la faille est là, il n'y a aucune limite au code qu'on peut exécuter. En bref, on est morts.

## Comment en trouver dans le code d'une application existante


## Activité / Exemple
L'application vous demande un nom d'utilisateur et vous tapez 
```sql
'); DROP DATABASE test; -- 
```

Ces données sont ensuite envoyées au serveur dans le code de l'application.



---
id: r27
title: Rencontre 27 - Injection SQL (défense)
sidebar_label: R27 - Injection SQL (défense)
draft: true
hide_table_of_contents: false
---


# Injection SQL (défense)

On ne devrait pas faire de **"SELECT * FROM table WHERE id = " + id + ";" **
On devrait faire un **"SELECT * FROM table WHERE id = ?;"** et passer le paramètre id en paramètre de la requête.

## Pourquoi c'est mieux côté sécurité?

Un paramètre est uniquement considéré comme des données et non du code.

Si on essaie une chaine d'injection elle va juste se retrouver dans les données mais aucune commande n'est exécutée.

## Pourquoi c'est mieux tout court

Quand on envoie **"SELECT * FROM table WHERE id = ?;"**:
- la requête est compilée par le moteur de base de données une fois pour 0.01$ (par exemple)
- la requête est uniquement exécutée par la suite pour 0.01$
- Si on exécute la requéte 1000 fois, on paie 0.01$ pour la compilation et 1000 * 0.01$ pour l'exécution environ 10$

Quand on concatène **"SELECT * FROM table WHERE id = " + id + ";"**:
- pour chaque id différent, cela donne une string différente
- si le code est différent, le moteur de BD doit recompiler
- pour 1000 requêtes avec des id différents, on va payer compilation et exécution à chaque fois
- on paie environ 20$

## Est-ce qu'il reste des failles d'injections SQL?

Certainement. Règle pour votre future carrière:
- traverser le code des applications sur lesquelles vous travaillerez pour chercher des concaténations de requêtes SQL
- éduquer patiemment et gentiment des collègues qui le font.

## TP / Correctif sur le code fourni

Pour le reste de la séance, tu vas devoir corriger le code de l'application du TP pour éviter les injections SQL.

RAPPEL : pour valider que ton correctif fonctionne, tu dois avoir un exploit qui :
1. permet de modifier les données en utilisant une injection SQL
2. l'exploit fonctionne sur le commit qui précède ton correctif
3. l'exploit ne fonctionne plus après ton correctif

Autrement dit, tu ne devrais commit ton correctif **UNIQUEMENT** si tu as validé que l'exploit est désamorcé.



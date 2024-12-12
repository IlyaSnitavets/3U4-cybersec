---
id: r24
title: Rencontre 24 - Chiffrement symétrique (attaque)
sidebar_label: R24 - Chiffrement symétrique (attaque)
draft: true
hide_table_of_contents: false
---



# Rencontre 12.2 : Encryption symmétrique, on attaque

## Un algo d'encryption symmétrique

Un couple de fonctions *encrypt(key, message)* et *decrypt(key, message)* qui permettent de 
1. transformer une message en bouillie illisible
2. récupérer le message à partir de la bouillie illisible pour peu qu'on utilise la même clé

## Le code de César, un vieil exemple

Un exemple avec un code de décalage (aussi appelé le code de César):
- "Upk35t3k350p2knzy4py4kopk4pk6zt2k" est le message encrypté, la bouillie
- la clé d'encryption est 11
- la personne qui décode doit en fait prendre la lettre qui est 11 rang plus bas sur la table d'encryption
- https://jorisdeguet.github.io/cesar.html

## Comment on peut casser ça

```
Le secret ne repose pas dans l'ignorance de l'algorithme mais dans l'ignorance de la clé!!
```

Donc essentiellement, pour casser le code de César, il suffit de trouver la clé. 

Pour cela on peut utiliser plusieurs techniques:
- essayer d'être malin
- y aller comme une grosse brute

### Exemple malin

Reprenons notre exemple de "Upk35t3k350p2knzy4py4kopk4pk6zt2k"
- il y a 2 symboles très très fréquents en français: l'espace et le 'e'
- on va compter les caractères dans la chaîne cryptée:
  - il y a 7 'k'
  - il y a 5 'p'
- on peut imaginer que le 'k' est l'espace ou que le 'k' est le 'e'
- la clé qui transforme espace en 'k' est 11
- la clé qui transforme 'e' en 'k' est 60
- si on décode avec la clé 11 on obtient "Je suis super content de te voir "
- si on décode avec la clé 60 on obtient "Zup8.y8p8.5u7ps439u39ptup9up,4y7p"

On voit un message qui fait du sens, un qui n'en fait pas. On en déduit que la clé doit être 11.

### Exemple malin 2

Mettons que tu peux :
1. choisir un message
2. accéder à la BD dans laquelle le message est stocké

Alors on peut juste mettre tous les caractères possibles dans le message et regarder ce qui ressort.
- "abcdefghijklmnopqrstuvwxyz" message de base
- "bcdefghijklmnopqrstuvwxyza" message encrypté
- ça nous donne directement la table de traduction lettre par lettre

Le problème ici est que l'algo d'encryptage fonctionne lettre par lettre:
- le caractère n est encodé dans le caractère n
- si on change un seul caractère dans le texte clair, il y a un seul caractère qui change dans le crypté
- on dit que l'algorithme est local

### Exemple brutal

Pour tous les décalages possibles, on décode le message et on regarde si le message décodé a du sens.

Si ton alphabet a 26 lettres, il y a 26 décalages possibles pas plus.

### Exercices

Retranscris tes découvertes dans un fichier **cesar.md** dans ton dossier / repo d'exercices.

- en utilisant https://jorisdeguet.github.io/cesar.html
- le message crypté est "dEzA163,3AGyGEBCy4z17.3"
- essaie de trouver le message en clair et la clé utilisée
- décris l'exploit que tu as utilisé
- valide tes réponses en encodant ton message clair avec la clé et vérifie que le crypté est le même



## Si il y a symétrique, il doit y avoir asymétrique




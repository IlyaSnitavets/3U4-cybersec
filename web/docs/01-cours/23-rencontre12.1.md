---
id: r23
title: Rencontre 23 - Hachage et fonction à sens unique
sidebar_label: R23 - Hachage et fonction à sens unique
draft: true
hide_table_of_contents: false
---

# Le hachage, une mesure de second rideau

## En quoi cela sécurise? 

Pourquoi cela sécurise?
```

```

https://fr.wikipedia.org/wiki/Fonction_à_sens_unique

## Pour quoi ça s'utilise

- On n'a pas besoin de l'information fournie pour l'application
- On a juste besoin de vérifier que c'est la même info qu'avant

## Comment ça s'implante en code

:warning: **Ne jamais implanter une fonction de crypto soi-même**: On n'a pas encore le niveau!

https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.hashalgorithm?view=net-8.0

L'algorithme le plus classique pour nous SHA256

### la grosse question, contre quelles attaques nous protège le changement de md5 vers SHA256

- crackstation : nope, ils ont aussi le reverse lookup pour tous les algos de hash classique, ça ne change rien
- devine le mot de passe en connaissant des infos persos : non plus, le mot de passe reste le même, juste le hash qui change

Alors donc:
- les hash sont plus longs donc la probabilité d'une collision (2 mots de passe qui donne le même hash est plus faible)
- autres attaques à chercher : fastcoll (Wang et Yu 2004).

## Est-ce qu'on veut saler notre mot de passe

Pour rappel, saler un mot de passe c'est:
- concaténer le mot de passe fourni par l'utilisateur avec une chaîne si possible complexe
- ensuite on hash
- ensuite on stocke dans la BD
- si le sel est spécifique à chaque utilisateur, il faudra alors le stocker dans la BD également

## bcrypt, le standard de l'industrie et pourquoi

- bcrypt ajoute un hash tout seul sur BlowFish
- bcrypt s'adapte aux resources de calcul qui augmente et peut devenir de plus en plu dur à calculer

Wow wow, comment ça il ajoute automatiquement un hash?
- en fait on tire au hasard un salt, on calcule un hash
- on stocke en clair le salt dans le résultat avec le hash
```
22 character salt and 31 character hash
```
- quand on veut comparer plus tard, on peut recalculer puisqu'on a le salt en clair

Explication de comment BCrypt marche [bcrypt](https://en.wikipedia.org/wiki/Bcrypt) 


https://www.youtube.com/watch?v=O6cmuiTBZVs

## utilsation de hash pour détecter une attaque

1. Bob qui développe une page web utilise un CDN pour charger jquery 1.8
2. il ajoute donc une balise **<script src="https://supercdn.com/1.8/jquery.min.js" ></script>"
3. il a un peu peur qu'un jour quelqu'un pirate le site supercdn.com et modifie le code de jquery.min.js pour faire des trucs
4. arrive alors l'attribut integrity
5. on y met le hash du code source correct
6. si un jour le navigateur télécharge le fichier calcule le hash et voit qu'il ne correspond pas, il n'exécute pas le code

Dans ce cas, une attaque devient beaucoup plus compliquée:
1. le pirate doit prendre le contrôle du site supercdn
2. le pirate doit effectuer une modification qui:
  - fait le truc méchant voulu en étant du javascript valide
  - donne le même hash que le code d'origine





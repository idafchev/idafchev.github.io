---
layout: default
description: A blog about information security, networking and technology
title: Home
---
{% for post in site.posts limit:1 %}
<div class="post">
    <h1 class="post-title">
      <a href="{{ post.url }}">
        {{ post.title }}
      </a>
    </h1>

    <span class="post-date">{{ post.date | date_to_string }}</span>

    {{ post.content }}
</div>
{% endfor %}


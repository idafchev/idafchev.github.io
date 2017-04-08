---
layout: default
---
### Blog Posts
<div class="bloglist">
{% for post in site.posts %}
	<small>{{ post.date | date_to_string }}</small>
	<h4 class="post-title"><a href="{{ post.url | replace_first: '/', '' }}">{{ post.title }}</a></h4>
	<p>{{ post.description }}</p>
{% unless forloop.last %}{% endunless %}
	<hr>
{% endfor %}
</div>

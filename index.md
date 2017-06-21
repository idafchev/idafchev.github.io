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

<div id="disqus_thread"></div>
<script>
var disqus_config = function () {
this.page.url = '{{ post.url }}';  // Replace PAGE_URL with your page's canonical URL variable
this.page.identifier = '{{ post.url }}'; // Replace PAGE_IDENTIFIER with your page's unique identifier variable
};
(function() { // DON'T EDIT BELOW THIS LINE
var d = document, s = d.createElement('script');
s.src = '//idafchev.disqus.com/embed.js';
s.setAttribute('data-timestamp', +new Date());
(d.head || d.body).appendChild(s);
})();
</script>
<noscript>Please enable JavaScript to view the <a href="https://disqus.com/?ref_noscript">comments powered by Disqus.</a></noscript>

{% endfor %}

{{ fullname }}
{{ underline }}

.. currentmodule:: {{ module }}

.. autoclass:: {{ objname }}

   {% block attributes %}
   {% if attributes %}
   .. rubric:: Attributes

   .. autosummary::
   {% for item in attributes %}
      {{ name }}.{{ item }}
   {%- endfor %}
   {% endif %}
   {% endblock %}

   {% block methods %}
   {% if methods %}
   .. rubric:: Methods
   
   .. autosummary::
   {% for item in methods %}
      {{ name }}.{{ item }}
   {%- endfor %}
   {% endif %}
   {% endblock %}

   {% if attributes %}
   ----------------
   Class attributes
   ----------------
   {% for item in attributes %}
   .. autoattribute:: {{ name }}.{{ item }}
   {%- endfor %}
   {% endif %}

   {% if methods %}
   -------------
   Class methods
   -------------
   {% for item in methods %}
   .. automethod:: {{ name }}.{{ item }}
   {%- endfor %}
   {% endif %}

  




{{ underline }}
{{ fullname }}
{{ underline }}

.. automodule:: {{ fullname }}
   :no-members:
   :no-show-inheritance:
   :no-inherited-members:
   :no-undoc-members:
   :no-special-members:
   :no-private-members:
   
   {% block functions %}
   {% if functions %}
   .. rubric:: Functions

   .. autosummary::
   {% for item in functions %}
      {{ item }}
   {%- endfor %}
   {% endif %}
   {% endblock %}

   {% block classes %}
   {% if classes %}

   .. rubric:: Classes

   .. autosummary::
      :template: myclass2.rst 
      :toctree:
   {% for item in classes %}
      {{ item }}
   {%- endfor %}

   .. rubric:: Classes diagram

   .. inheritance-diagram:: {% for item in classes %} {{item}} {% endfor %}

   {% endif %}
   {% endblock %}

   {% block exceptions %}
   {% if exceptions %}
   .. rubric:: Exceptions

   .. autosummary::
      :template: myexception.rst 
      :toctree:
   {% for item in exceptions %}
      {{ item }}
   {%- endfor %}
   {% endif %}
   {% endblock %}

   {% block data %}
   {% if data %}
   .. rubric:: Module data
   .. autosummary::
   {% for item in data %}
      {{ item }}
   {%- endfor %}
   {% endif %}
   {% endblock %}

   {% block html %}
   .. raw:: html
      
      <br>
      <hr width="75%">  
      <br>

   {% endblock %}

   {% if data %}
   -----------
   Module data
   -----------
   {% for item in data %}
   .. autodata:: {{ item }}
   {%- endfor %}
   {% endif %}

   {% if functions %}
   ---------
   Functions
   ---------
   {% for item in functions %}
   .. autofunction:: {{item}}
   {%- endfor %}
   {% endif %}


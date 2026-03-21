<html>
  <title>Logger Config</title>
    <head>
      <script src="//ajax.googleapis.com/ajax/libs/jquery/1.11.2/jquery.min.js"></script>
      <style>
        @media (prefers-color-scheme: dark) {
          body { background: #0d0d1a; color: #e0e0e0; }
          table { border-color: #444; }
          th, td { border-color: #444; }
          select { background: #1e1e2e; color: #e0e0e0; border-color: #444; }
        }
      </style>
    </head>
    <body>
      <table border=1 cellpadding=0 cellspacing=0 align=left>
        <tr>
          <th>Logger</th>
          <th>Level</th>
        </tr>
        $loggers:{ logger |    
          <tr>
            <td>$logger.name$</td>
            <td>
              <select id="$logger.name$" name="level"  class="selectlevels" data-loglevel="$logger.level$">
                $levels:{ level |
                  <option value='$level$'>$level$</option>	
                }$
              </select>
            </td>
          </tr>
        }$
      </table>
      <script>
        \$(document).ready(function() {
          // For every logger changed the select to match the current level.
          \$('.selectlevels').each(function() { 
            \$(this).val(\$(this).data('loglevel')); 
          });
          // Every time a logger value is changed post the logger name and new level.        
          \$('.selectlevels').change(function() { 
            \$.post("/logconfig", 
                   { logger : \$(this).attr('id'), level : \$(this).val() },
                   function() {
                     // Reload the page so the new logger value is visible.  
                     location.reload();
                   }
            );	
          });
        });
      </script>
    </body>
</html>

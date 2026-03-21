<!--
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 -->
 <html>
  <head>
    <title>Aurora $cluster_name$ agents</title>
    <link href="/assets/bower_components/bootstrap/dist/css/bootstrap.min.css" rel="stylesheet" />
    <style>
      th.sortable { cursor: pointer; user-select: none; white-space: nowrap; }
      th.sortable::after { content: ' \2195'; color: #aaa; font-size: 0.8em; }
      th.sort-asc::after { content: ' \25B2'; color: #333; font-size: 0.8em; }
      th.sort-desc::after { content: ' \25BC'; color: #333; font-size: 0.8em; }
      @media (prefers-color-scheme: dark) {
        body { background: #0d0d1a; color: #e0e0e0; }
        a { color: #6eb3f5; }
        .table { color: #e0e0e0; }
        .table-striped > tbody > tr:nth-of-type(odd) { background: #1e1e2e; }
        .table-hover > tbody > tr:hover { background: #2a3a50; }
        th { background: #16213e; color: #6eb3f5; }
        th.sort-asc::after, th.sort-desc::after { color: #6eb3f5; }
        th.sortable::after { color: #555; }
      }
    </style>
  </head>
  <body>
    <h2>Agent Hosts</h2>
    <table id="agents-table" class="table table-striped table-condensed table-hover">
      <thead>
        <tr>
          <th class="sortable" data-col="0">Host</th>
          <th class="sortable" data-col="1">Agent ID</th>
          <th class="sortable" data-col="2">Maintenance mode</th>
          <th class="sortable" data-col="3">Last Seen</th>
          <th class="sortable" data-col="4">Attributes</th>
        </tr>
      </thead>
      <tbody>
        $agents:{ agent |
        <tr>
          <td><a href="/thermos/agent/$agent.id$/">$agent.host$</a></td>
          <td>$agent.id$</td>
          <td>$agent.mode$</td>
          <td data-ms="$agent.lastSeenMs$"><span class="last-seen-fmt">$agent.lastSeenMs$</span></td>
          <td>$agent.attributes$</td>
        </tr>
        }$
      </tbody>
    </table>
    <script>
    (function () {
      // Format epoch-ms timestamps as relative "X ago" strings with full datetime as tooltip
      function timeAgo(ms) {
        var sec = Math.floor((Date.now() - ms) / 1000);
        if (sec < 0)   return 'just now';
        if (sec < 60)  return sec + 's ago';
        var min = Math.floor(sec / 60);
        if (min < 60)  return min + 'm ago';
        var hr = Math.floor(min / 60);
        if (hr < 24)   return hr + 'h ago';
        var day = Math.floor(hr / 24);
        if (day < 30)  return day + 'd ago';
        var mo = Math.floor(day / 30);
        if (mo < 12)   return mo + 'mo ago';
        return Math.floor(mo / 12) + 'y ago';
      }

      document.querySelectorAll('.last-seen-fmt').forEach(function (el) {
        var ms = parseInt(el.textContent, 10);
        if (ms > 0) {
          el.textContent = timeAgo(ms);
          el.title = new Date(ms).toLocaleString();
        } else {
          el.textContent = '-';
        }
      });

      // Sortable table
      var table = document.getElementById('agents-table');
      var tbody = table.querySelector('tbody');
      var currentCol = -1;
      var ascending = true;

      table.querySelectorAll('th.sortable').forEach(function (th) {
        th.addEventListener('click', function () {
          var col = parseInt(th.getAttribute('data-col'), 10);
          if (currentCol === col) {
            ascending = !ascending;
          } else {
            currentCol = col;
            ascending = true;
          }

          table.querySelectorAll('th.sortable').forEach(function (h) {
            h.classList.remove('sort-asc', 'sort-desc');
          });
          th.classList.add(ascending ? 'sort-asc' : 'sort-desc');

          var rows = Array.from(tbody.querySelectorAll('tr'));
          rows.sort(function (a, b) {
            var aCell = a.querySelectorAll('td')[col];
            var bCell = b.querySelectorAll('td')[col];

            // Last Seen column: numeric sort by data-ms attribute
            if (aCell.hasAttribute('data-ms')) {
              var aMs = parseInt(aCell.getAttribute('data-ms'), 10) || 0;
              var bMs = parseInt(bCell.getAttribute('data-ms'), 10) || 0;
              return ascending ? aMs - bMs : bMs - aMs;
            }

            var aVal = aCell.textContent.trim().toLowerCase();
            var bVal = bCell.textContent.trim().toLowerCase();
            return ascending ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
          });

          rows.forEach(function (r) { tbody.appendChild(r); });
        });
      });
    }());
    </script>
  </body>
</html>

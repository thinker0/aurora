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
  <title>Aurora Struct Dump</title>
  <head>
    $id$
    <style>
      @media (prefers-color-scheme: dark) {
        body { background: #0d0d1a; color: #e0e0e0; }
      }
    </style>
  </head>
  <body>
    <pre>
      $structPretty$
    </pre>

    $if(exception)$
      <span style="color:#d63c39">Exception: $exception$</span>
    $endif$
  </body>
</html>

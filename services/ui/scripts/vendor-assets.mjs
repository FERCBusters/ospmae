import fs from 'node:fs';
import path from 'node:path';

function copyIfExists(src, dest) {
  if (!fs.existsSync(src)) {
    console.warn(`Skip (missing): ${src}`);
    return;
  }
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(src, dest);
  console.log(`Vendored ${src} -> ${dest}`);
}

const root = process.cwd();
const nm = (...parts) => path.join(root, 'node_modules', ...parts);
const out = (...parts) => path.join(root, 'public', 'vendor', ...parts);

// Bootstrap + icons
copyIfExists(nm('bootstrap', 'dist', 'css', 'bootstrap.min.css'), out('bootstrap', 'bootstrap.min.css'));
copyIfExists(nm('bootstrap', 'dist', 'js', 'bootstrap.bundle.min.js'), out('bootstrap', 'bootstrap.bundle.min.js'));

copyIfExists(nm('bootstrap-icons', 'font', 'bootstrap-icons.min.css'), out('bootstrap-icons', 'bootstrap-icons.min.css'));
copyIfExists(nm('bootstrap-icons', 'font', 'fonts', 'bootstrap-icons.woff'), out('bootstrap-icons', 'fonts', 'bootstrap-icons.woff'));
copyIfExists(nm('bootstrap-icons', 'font', 'fonts', 'bootstrap-icons.woff2'), out('bootstrap-icons', 'fonts', 'bootstrap-icons.woff2'));

// D3
copyIfExists(nm('d3', 'dist', 'd3.min.js'), out('d3', 'd3.min.js'));

// jsPDF (for client-side exports)
copyIfExists(nm('jspdf', 'dist', 'jspdf.umd.min.js'), out('jspdf', 'jspdf.umd.min.js'));

// MOSP design system
copyIfExists(nm('@FERCBusters', 'mosp-design-system', 'dist', 'styles.css'), out('mosp-design-system', 'styles.css'));
copyIfExists(nm('@FERCBusters', 'mosp-design-system', 'dist', 'app.js'), out('mosp-design-system', 'app.js'));
copyIfExists(nm('@FERCBusters', 'mosp-design-system', 'dist', 'BUILD_INFO.txt'), out('mosp-design-system', 'BUILD_INFO.txt'));

console.log('Vendored assets into public/vendor');

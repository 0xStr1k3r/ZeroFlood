// ZeroFlood Documentation - Fixed Version

const titleMap = {
    'home.md': 'Welcome to ZeroFlood',
    'installation.md': 'Installation',
    'quickstart.md': 'Quick Start Guide',
    'architecture.md': 'System Architecture',
    'detection.md': 'Attack Detection',
    'mitigation.md': 'Mitigation System',
    'llm.md': 'LLM Integration',
    'api.md': 'API Reference',
    'configuration.md': 'Configuration',
    'troubleshooting.md': 'Troubleshooting'
};

// Simple Markdown to HTML converter
function mdToHtml(text) {
    if (!text) return '<p>No content</p>';
    
    let html = text;
    
    // Headers
    html = html.replace(/^#### (.*$)/gm, '<h4>$1</h4>');
    html = html.replace(/^### (.*$)/gm, '<h3>$1</h3>');
    html = html.replace(/^## (.*$)/gm, '<h2>$1</h2>');
    html = html.replace(/^# (.*$)/gm, '<h1>$1</h1>');
    
    // Bold and Italic
    html = html.replace(/\*\*\*(.*?)\*\*\*/g, '<strong><em>$1</em></strong>');
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');
    
    // Code blocks
    html = html.replace(/```(\w*)\n([\s\S]*?)```/g, '<div class="code-group"><div class="code-header"><span class="code-lang">$1</span></div><pre><code>$2</code></pre></div>');
    
    // Inline code
    html = html.replace(/`([^`\n]+)`/g, '<code class="inline">$1</code>');
    
    // Links
    html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank">$1</a>');
    
    // Horizontal rules
    html = html.replace(/^---$/gm, '<hr>');
    
    // Process tables line by line
    const lines = html.split('\n');
    const resultLines = [];
    let inTable = false;
    let tableRows = [];
    
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        
        // Detect table rows
        if (line.includes('|') && !line.match(/^\s*\|[\s\-:]+\|/)) {
            if (!inTable) {
                inTable = true;
                tableRows = [];
            }
            const cells = line.split('|').filter(c => c.trim());
            tableRows.push(cells.map(c => c.trim()));
        } else {
            if (inTable && tableRows.length > 0) {
                // Build table HTML
                if (tableRows.length >= 2 && tableRows[1].every(c => /^[-:]+$/.test(c))) {
                    // Has header row
                    resultLines.push('<table class="doc-table"><thead><tr>');
                    tableRows[0].forEach(cell => resultLines.push('<th>' + cell + '</th>'));
                    resultLines.push('</tr></thead><tbody>');
                    for (let j = 2; j < tableRows.length; j++) {
                        resultLines.push('<tr>');
                        tableRows[j].forEach(cell => resultLines.push('<td>' + cell + '</td>'));
                        resultLines.push('</tr>');
                    }
                    resultLines.push('</tbody></table>');
                } else {
                    // Simple table
                    resultLines.push('<table class="doc-table"><tbody>');
                    tableRows.forEach(row => {
                        resultLines.push('<tr>');
                        row.forEach(cell => resultLines.push('<td>' + cell + '</td>'));
                        resultLines.push('</tr>');
                    });
                    resultLines.push('</tbody></table>');
                }
                tableRows = [];
            }
            inTable = false;
            resultLines.push(line);
        }
    }
    
    // Close table if ends with table
    if (inTable && tableRows.length > 0) {
        resultLines.push('<table class="doc-table"><tbody>');
        tableRows.forEach(row => {
            resultLines.push('<tr>');
            row.forEach(cell => resultLines.push('<td>' + cell + '</td>'));
            resultLines.push('</tr>');
        });
        resultLines.push('</tbody></table>');
    }
    
    html = resultLines.join('\n');
    
    // Lists
    html = html.replace(/^[\-\*] (.*$)/gm, '<li>$1</li>');
    html = html.replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>');
    
    html = html.replace(/^\d+\. (.*$)/gm, '<li>$1</li>');
    
    // Paragraphs - split by double newlines
    const paragraphs = html.split(/\n\n+/);
    const paraResult = [];
    
    paragraphs.forEach(p => {
        p = p.trim();
        if (!p) return;
        // Skip if already HTML element
        if (p.match(/^<(h[1-4]|ul|ol|table|div|pre|blockquote|hr)/)) {
            paraResult.push(p);
        } else {
            // Convert single newlines to <br>
            paraResult.push('<p>' + p.replace(/\n/g, '<br>') + '</p>');
        }
    });
    
    html = paraResult.join('\n');
    
    // Clean up
    html = html.replace(/<p><\/p>/g, '');
    html = html.replace(/<p>(<h[1-4]>)/g, '$1');
    html = html.replace(/(<\/h[1-4]>)<\/p>/g, '$1');
    html = html.replace(/<p>(<ul>)/g, '$1');
    html = html.replace(/(<\/ul>)<\/p>/g, '$1');
    html = html.replace(/<p>(<table)/g, '$1');
    html = html.replace(/(<\/table>)<\/p>/g, '$1');
    html = html.replace(/<p>(<div)/g, '$1');
    html = html.replace(/(<\/div>)<\/p>/g, '$1');
    html = html.replace(/<p>(<pre)/g, '$1');
    html = html.replace(/(<\/pre>)<\/p>/g, '$1');
    html = html.replace(/<p>(<hr>)/g, '$1');
    html = html.replace(/(<hr>)<\/p>/g, '$1');
    
    return html;
}

// Load page
function loadPage(file) {
    const contentBody = document.getElementById('content-body');
    const pageTitle = document.getElementById('page-title');
    
    // Update navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
        if (item.dataset.file === file) {
            item.classList.add('active');
        }
    });
    
    // Update title
    pageTitle.textContent = titleMap[file] || 'Documentation';
    
    // Show loading
    contentBody.innerHTML = '<div class="loading">Loading...</div>';
    
    // Fetch and render
    fetch(file)
        .then(response => {
            if (!response.ok) throw new Error('File not found: ' + file);
            return response.text();
        })
        .then(markdown => {
            contentBody.innerHTML = mdToHtml(markdown);
        })
        .catch(error => {
            contentBody.innerHTML = '<div class="error-box"><h3>Error</h3><p>' + error.message + '</p></div>';
        });
    
    // Update URL
    window.location.hash = file;
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Navigation clicks
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            loadPage(this.dataset.file);
        });
    });
    
    // Load initial page
    const hash = window.location.hash.slice(1);
    loadPage(hash || 'home.md');
});
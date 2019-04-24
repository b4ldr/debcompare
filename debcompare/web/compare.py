from flask import Blueprint, current_app, render_template, jsonify
from debcompare.compare import Differ


bp = Blueprint('compare', __name__, url_prefix='/compare')


@bp.route('<source_pkg>/<old_version>/<new_version>')
def compare(source_pkg, old_version, new_version):
    '''compare two versions'''
    # TOD: force, working_dir
    fixed_cves = current_app.packages_cve.get_cves(source_pkg, new_version)
    differ = Differ(
        source_pkg,
        old_version,
        new_version,
        fixed_cves,
    )
    return render_template('compare.html', differ=differ)

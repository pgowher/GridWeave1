"""GridWeave research workflows, with the full legacy generator still available."""
import argparse,json,sys
from . import __version__


def main(argv=None):
    argv=list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0]=='legacy':
        from htgl_dataset_generator.cli.main import main as legacy
        return legacy(argv[1:])
    p=argparse.ArgumentParser(prog='gridweave',description='Oracle-separated, signed metadata datasets ready for VERCLO')
    p.add_argument('--version',action='version',version=__version__)
    commands=p.add_subparsers(dest='command',required=True)
    g=commands.add_parser('generate');g.add_argument('--output',required=True);g.add_argument('--seed')
    g.add_argument('--scales',type=int,nargs='+',default=[1,2,4]);g.add_argument('--strategy',choices=['auto','exact','greedy','all','random'],default='auto')
    g.add_argument('--max-states',type=int,default=100000);g.add_argument('--include-audit',action='store_true')
    g.add_argument('--scenarios',nargs='+')
    v=commands.add_parser('validate');v.add_argument('dataset');v.add_argument('--expected-sha256')
    r=commands.add_parser('run');r.add_argument('dataset');r.add_argument('--output',required=True)
    args=p.parse_args(argv)
    from .dataset import generate,validate,run
    try:
        if args.command=='generate':result=generate(args.output,seed=args.seed,scales=args.scales,strategy=args.strategy,
                                max_states=args.max_states,include_audit=args.include_audit,scenario_ids=args.scenarios)
        elif args.command=='validate':result=validate(args.dataset,expected_sha256=args.expected_sha256)
        else:result=run(args.dataset,args.output)
        print(json.dumps(result,indent=2))
        return 3 if result.get('mismatch_count',0) else 0
    except (ValueError,OSError,RuntimeError) as e:
        print(json.dumps({'status':'ERROR','error':str(e)}),file=sys.stderr);return 2


if __name__=='__main__':raise SystemExit(main())
